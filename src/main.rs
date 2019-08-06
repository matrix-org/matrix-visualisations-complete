extern crate actix_web;
extern crate awc;
extern crate base64;
extern crate futures;
extern crate futures_cpupool;
extern crate indolentjson;
extern crate openssl;
extern crate percent_encoding;
extern crate r2d2_postgres;
extern crate serde_derive;
#[macro_use]
extern crate serde_json;
extern crate sodiumoxide;

pub mod federation;
pub mod postgres;

use std::env::args;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::process::exit;
use std::sync::{Arc, Mutex};

use actix_web::{guard, web, App, HttpRequest, HttpResponse, HttpServer};
use futures_cpupool::CpuPool;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use r2d2_postgres::{PostgresConnectionManager, TlsMode};
use sodiumoxide::crypto::sign::ed25519::{keypair_from_seed, SecretKey, Seed};

use crate::federation::ancestors as federation_ancestors;
use crate::federation::deepest as federation_deepest;
use crate::federation::descendants as federation_descendants;
use crate::federation::serv_cert;
use crate::federation::stop as federation_stop;
use crate::federation::FederationData;
use crate::postgres::ancestors as pg_ancestors;
use crate::postgres::deepest as pg_deepest;
use crate::postgres::descendants as pg_descendants;
use crate::postgres::Database;

fn main() -> std::io::Result<()> {
    let args: Vec<String> = args().collect();

    if args.len() < 2 || (args[1] != "postgres" && args[1] != "federation") {
        eprintln!("Usage: cargo run --release [postgres / federation]");
        exit(-1);
    }

    let mut ssl_builder =
        SslAcceptor::mozilla_intermediate(SslMethod::tls()).expect("Failed to create SSL builder");
    ssl_builder
        .set_private_key_file("key.pem", SslFiletype::PEM)
        .expect("Failed to load TLS private key");
    ssl_builder
        .set_certificate_chain_file("cert.pem")
        .expect("Failed to load TLS certificate");

    if args[1] == "postgres" {
        println!("Backend in postgres mode");

        let cpu_pool = CpuPool::new_num_cpus();
        let manager = PostgresConnectionManager::new(
            "postgres://synapse_user@localhost/synapse",
            TlsMode::None,
        )
        .unwrap();
        let pg_pool = r2d2::Pool::new(manager).expect("Failed to create pool");

        let db = web::Data::new(Database { cpu_pool, pg_pool });

        HttpServer::new(move || {
            App::new()
                .register_data(db.clone()) // The database connection manager will be shared by all the handlers
                .route(
                    "/visualisations/*",
                    web::route().guard(guard::Options()).to(|_: HttpRequest| {
                        HttpResponse::Ok()
                            .header("Access-Control-Allow-Origin", "*")
                            .header("Access-Control-Allow-Methods", "GET, POST")
                            .header(
                                "Access-Control-Allow-Headers",
                                "Origin, X-Requested-With, Content-Type, Accept",
                            )
                            .body("")
                    }),
                )
                .service(web::resource("/visualisations/deepest/{roomId}").to_async(pg_deepest))
                .service(web::resource("/visualisations/ancestors/{roomId}").to_async(pg_ancestors))
                .service(
                    web::resource("/visualisations/descendants/{roomId}").to_async(pg_descendants),
                )
                .service(web::resource("/visualisations/stop/{roomId}").to(|| {
                    HttpResponse::Ok()
                        .header("Access-Control-Allow-Origin", "*")
                        .header("Access-Control-Allow-Methods", "GET, POST")
                        .header(
                            "Access-Control-Allow-Headers",
                            "Origin, X-Requested-With, Content-Type, Accept",
                        )
                        .body("No need to leave a room with the postgres backend")
                }))
        })
        .bind_ssl("127.0.0.1:8482", ssl_builder)?
        .run()
    } else if args[1] == "federation" {
        if args.len() < 6 {
            eprintln!("Usage: cargo run --release federation <target_addr> <target_name> <server_name> <username>");
            exit(-1);
        }

        println!("Backend in federation mode");

        let (public_key, secret_key, key_name) =
            key_info(&format!("{}.signing.key", args[4].clone()));

        let cpu_pool = CpuPool::new_num_cpus();

        let fd = web::Data::new(FederationData {
            cpu_pool,
            target_addr: args[2].clone(),
            target_name: args[3].clone(),
            room_id: String::new(),

            server_name: args[4].clone(),
            username: args[5].clone(),
            public_key,
            secret_key,
            key_name,

            connected: Arc::new(Mutex::new(false)),
            join_event: Arc::new(Mutex::new(None)),
        });

        HttpServer::new(move || {
            App::new()
                .register_data(fd.clone()) // Data for the federation which will be shared by all the handlers
                .route(
                    "/visualisations/*",
                    web::route().guard(guard::Options()).to(|_: HttpRequest| {
                        HttpResponse::Ok()
                            .header("Access-Control-Allow-Origin", "*")
                            .header("Access-Control-Allow-Methods", "GET, POST")
                            .header(
                                "Access-Control-Allow-Headers",
                                "Origin, X-Requested-With, Content-Type, Accept",
                            )
                            .body("")
                    }),
                )
                .service(
                    web::resource("/visualisations/deepest/{roomId}").to_async(federation_deepest),
                )
                .service(
                    web::resource("/visualisations/ancestors/{roomId}")
                        .to_async(federation_ancestors),
                )
                .service(
                    web::resource("/visualisations/descendants/{roomId}")
                        .to_async(federation_descendants),
                )
                .service(web::resource("/visualisations/stop/{roomId}").to_async(federation_stop))
                .service(web::resource("/_matrix/key/v2/server/{keyId}").to_async(serv_cert))
        })
        .bind_ssl("127.0.0.1:8482", ssl_builder)?
        .run()
    } else {
        eprintln!("Unknown mode");
        Ok(())
    }
}

fn key_info(path: &str) -> (String, SecretKey, String) {
    let file = File::open(path).expect("Failed to open the signing key's file");
    let mut buf_reader = BufReader::new(file);
    let mut contents = String::new();

    buf_reader
        .read_to_string(&mut contents)
        .expect("Failed to read the signing key's file");
    let key_name =
        contents
            .as_str()
            .split_ascii_whitespace()
            .take(2)
            .fold(String::new(), |acc, x| {
                if acc.is_empty() {
                    x.to_string()
                } else {
                    acc + ":" + x
                }
            });

    let seed = contents
        .as_str()
        .split_ascii_whitespace()
        .nth(2)
        .expect("No seed found in the signing key's file");
    let seed = Seed::from_slice(
        base64::decode_config(seed.as_bytes(), base64::STANDARD_NO_PAD)
            .expect("Failed to decode the seed")
            .as_slice(),
    )
    .expect("Failed to parse the seed");

    let (public_key, secret_key) = keypair_from_seed(&seed);
    let public_key = base64::encode_config(public_key.as_ref(), base64::STANDARD_NO_PAD);

    (public_key, secret_key, key_name)
}
