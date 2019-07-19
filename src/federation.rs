use actix_web::{web, Error, HttpResponse};
use futures::Future;
use futures_cpupool::CpuPool;

pub struct FederationData {
    pub cpu_pool: CpuPool,

    pub target: String,
    pub room_id: String,

    pub server_name: String,
    pub username: String,

    pub connected: bool,
}

pub fn deepest(path: web::Path<String>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    Box::new(futures::future::ok(
        HttpResponse::Ok()
            .content_type("application/json")
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST")
            .header(
                "Access-Control-Allow-Headers",
                "Origin, X-Requested-With, Content-Type, Accept",
            )
            .body(&format!("Deepest federated event for the room: {}", path)),
    ))
}

pub fn stop() -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    Box::new(futures::future::ok(
        HttpResponse::Ok()
            .content_type("application/json")
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST")
            .header(
                "Access-Control-Allow-Headers",
                "Origin, X-Requested-With, Content-Type, Accept",
            )
            .body("Stopping the federated backend"),
    ))
}

pub fn serv_cert(_: web::Path<String>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    Box::new(futures::future::ok(
        HttpResponse::Ok()
            .content_type("application/json")
            .body("The cert of the server"),
    ))
}
