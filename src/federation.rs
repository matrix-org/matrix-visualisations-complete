use std::sync::{Arc, Mutex};

use actix_web::{web, Error, HttpResponse};
use awc::Client;
use futures::{future, Future};
use futures_cpupool::CpuPool;
use serde::Serialize;
use serde_derive::Deserialize;
use serde_derive::Serialize as SerDerive;
use serde_json::Value as JsonValue;
use sodiumoxide::crypto::sign::SecretKey;

#[derive(Clone)]
pub struct FederationData {
    pub cpu_pool: CpuPool,

    pub target_addr: String,
    pub target_name: String,
    pub room_id: String,

    pub server_name: String,
    pub username: String,
    pub secret_key: SecretKey,
    pub key_name: String,

    pub connected: Arc<Mutex<bool>>,
    pub join_event: Arc<Mutex<Option<JsonValue>>>,
}

#[derive(SerDerive)]
struct RequestJson {
    method: String,
    uri: String,
    origin: String,
    destination: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<JsonValue>,
}

#[derive(Debug, Deserialize, SerDerive)]
struct MakeJoinResponse {
    room_version: String,
    event: JsonValue,
}

pub fn deepest(
    (room_id, fd): (web::Path<String>, web::Data<FederationData>),
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let client = Client::default();
    let path = format!(
        "/_matrix/federation/v1/make_join/{}/{}",
        room_id,
        percent_encoding::utf8_percent_encode(
            &format!("@{}:{}", fd.username, fd.server_name),
            percent_encoding::USERINFO_ENCODE_SET,
        )
    );

    let fd_clone = fd.clone();

    Box::new(
        client
            .get(&format!("http://{}{}", fd.target_addr, path))
            .header(
                "Authorization",
                request_json(
                    "GET",
                    &fd.server_name,
                    &fd.secret_key,
                    &fd.key_name,
                    &fd.target_name,
                    &path,
                    None,
                ),
            )
            .send()
            .map_err(|err| {
                actix_web::error::ErrorInternalServerError(format!(
                    "Error sending /make_join: {}",
                    err
                ))
            })
            .and_then(move |mut response| {
                if response.status().is_success() {
                    future::Either::A(response.json::<MakeJoinResponse>().limit(5000).map_err(
                        |err| {
                            actix_web::error::ErrorInternalServerError(format!(
                                "Error sending /make_join: {}",
                                err
                            ))
                        },
                    ))
                } else {
                    future::Either::B(futures::future::err(actix_web::error::ErrorUnauthorized(
                        "Unauthorized by the resident HS",
                    )))
                }
            })
            .and_then(move |json| {
                let pruned_event = prune_event(
                    serde_json::to_value(json.event.clone()).expect("Failed to serialize"),
                );

                let esig = event_signature(&pruned_event, &fd.secret_key);

                let mut event = json.event;

                event["signatures"]
                    .as_object_mut()
                    .unwrap()
                    .insert(fd.server_name.clone(), json!({ fd.key_name.clone(): esig }));

                *fd.join_event.lock().unwrap() = Some(event.clone());

                let path = path.as_str().replace("make", "send");

                client
                    .put(&format!("http://{}{}", fd.target_addr, path))
                    .header(
                        "Authorization",
                        request_json(
                            "PUT",
                            &fd.server_name,
                            &fd.secret_key,
                            &fd.key_name,
                            &fd.target_name,
                            &path,
                            Some(event.clone()),
                        ),
                    )
                    .send_json(&event)
                    .map_err(|err| {
                        actix_web::error::ErrorInternalServerError(format!(
                            "Could not send /send_join request: {}",
                            err
                        ))
                    })
            })
            .and_then(move |response| {
                if response.status().is_success() {
                    *fd_clone.connected.lock().unwrap() = true;

                    let json: JsonValue = fd_clone.join_event.lock().unwrap().clone().unwrap();

                    let response_object = json!({ "events": [json] });

                    let response_string = serde_json::to_string(&response_object)
                        .expect("Failed to serialize the response object");

                    future::ok(
                        HttpResponse::Ok()
                            .content_type("application/json")
                            .header("Access-Control-Allow-Origin", "*")
                            .header("Access-Control-Allow-Methods", "GET, POST")
                            .header(
                                "Access-Control-Allow-Headers",
                                "Origin, X-Requested-With, Content-Type, Accept",
                            )
                            .body(response_string),
                    )
                } else {
                    future::ok(
                        HttpResponse::Forbidden()
                            .content_type("application/json")
                            .header("Access-Control-Allow-Origin", "*")
                            .header("Access-Control-Allow-Methods", "GET, POST")
                            .header(
                                "Access-Control-Allow-Headers",
                                "Origin, X-Requested-With, Content-Type, Accept",
                            )
                            .body("Joining this room is forbidden"),
                    )
                }
            }),
    )
}

pub fn stop(
    (room_id, fd): (web::Path<String>, web::Data<FederationData>),
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let client = Client::default();
    let path = format!(
        "/_matrix/federation/v1/make_leave/{}/{}",
        room_id,
        percent_encoding::utf8_percent_encode(
            &format!("@{}:{}", fd.username, fd.server_name),
            percent_encoding::USERINFO_ENCODE_SET,
        )
    );

    let fd_clone = fd.clone();

    Box::new(
        client
            .get(&format!("http://{}{}", fd.target_addr, path))
            .header(
                "Authorization",
                request_json(
                    "GET",
                    &fd.server_name,
                    &fd.secret_key,
                    &fd.key_name,
                    &fd.target_name,
                    &path,
                    None,
                ),
            )
            .send()
            .map_err(|err| {
                actix_web::error::ErrorInternalServerError(format!(
                    "Error sending /make_leave: {}",
                    err
                ))
            })
            .and_then(move |mut response| {
                if response.status().is_success() {
                    future::Either::A(response.json::<MakeJoinResponse>().limit(5000).map_err(
                        |err| {
                            actix_web::error::ErrorInternalServerError(format!(
                                "Error making /make_leave: {}",
                                err
                            ))
                        },
                    ))
                } else {
                    future::Either::B(futures::future::err(actix_web::error::ErrorUnauthorized(
                        "Unauthorized by the resident HS",
                    )))
                }
            })
            .and_then(move |json| {
                let pruned_event = prune_event(
                    serde_json::to_value(json.event.clone()).expect("Failed to serialize"),
                );

                let esig = event_signature(&pruned_event, &fd.secret_key);

                let mut event = json.event;

                event["signatures"]
                    .as_object_mut()
                    .unwrap()
                    .insert(fd.server_name.clone(), json!({ fd.key_name.clone(): esig }));

                let path = path.as_str().replace("make", "send");

                client
                    .put(&format!("http://{}{}", fd.target_addr, path))
                    .header(
                        "Authorization",
                        request_json(
                            "PUT",
                            &fd.server_name,
                            &fd.secret_key,
                            &fd.key_name,
                            &fd.target_name,
                            &path,
                            Some(event.clone()),
                        ),
                    )
                    .send_json(&event)
                    .map_err(|err| {
                        actix_web::error::ErrorInternalServerError(format!(
                            "Could not send /send_leave request: {}",
                            err
                        ))
                    })
            })
            .and_then(move |response| {
                if response.status().is_success() {
                    *fd_clone.connected.lock().unwrap() = true;

                    future::ok(
                        HttpResponse::Ok()
                            .content_type("application/json")
                            .header("Access-Control-Allow-Origin", "*")
                            .header("Access-Control-Allow-Methods", "GET, POST")
                            .header(
                                "Access-Control-Allow-Headers",
                                "Origin, X-Requested-With, Content-Type, Accept",
                            )
                            .body("Room left"),
                    )
                } else {
                    future::ok(
                        HttpResponse::Forbidden()
                            .content_type("application/json")
                            .header("Access-Control-Allow-Origin", "*")
                            .header("Access-Control-Allow-Methods", "GET, POST")
                            .header(
                                "Access-Control-Allow-Headers",
                                "Origin, X-Requested-With, Content-Type, Accept",
                            )
                            .body("Leaving this room is forbidden"),
                    )
                }
            }),
    )
}

pub fn serv_cert(_: web::Path<String>) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    println!("Key requested");

    Box::new(futures::future::ok(
        HttpResponse::Ok()
            .content_type("application/json")
            .body("The cert of the server"),
    ))
}

fn event_signature(event_object: &JsonValue, signing_key: &SecretKey) -> String {
    let bytes = make_canonical(event_object).expect("Failed make_canonical");
    let signature = sodiumoxide::crypto::sign::ed25519::sign_detached(&bytes, signing_key);
    let base64_signature = base64::encode_config(&signature, base64::STANDARD_NO_PAD);

    base64_signature
}

fn prune_event(event_object: JsonValue) -> JsonValue {
    let etype = event_object["type"].as_str().unwrap();

    let mut content = match event_object["content"].clone() {
        JsonValue::Object(obj) => obj,
        _ => unreachable!(), // Content is always an object
    };

    let allowed_keys = [
        "event_id",
        "sender",
        "room_id",
        "content",
        "type",
        "state_key",
        "depth",
        "prev_events",
        "prev_state",
        "auth_events",
        "origin",
        "origin_server_ts",
        "membership",
    ];

    let val = match event_object.clone() {
        serde_json::Value::Object(obj) => obj,
        _ => unreachable!(), // Events always serialize to an object
    };

    let mut val: serde_json::Map<_, _> = val
        .into_iter()
        .filter(|(k, _)| allowed_keys.contains(&(k as &str)))
        .collect();

    let mut new_content = serde_json::Map::new();

    let mut copy_content = |key: &str| {
        if let Some(v) = content.remove(key) {
            new_content.insert(key.to_string(), v);
        }
    };

    match &etype[..] {
        "m.room.member" => copy_content("membership"),
        "m.room.create" => copy_content("creator"),
        "m.room.join_rules" => copy_content("join_rule"),
        "m.room.aliases" => copy_content("aliases"),
        "m.room.history_visibility" => copy_content("history_visibility"),
        "m.room.power_levels" => {
            for key in &[
                "ban",
                "events",
                "events_default",
                "kick",
                "redact",
                "state_default",
                "users",
                "users_default",
            ] {
                copy_content(key);
            }
        }
        _ => {}
    }

    val.insert(
        "content".to_string(),
        serde_json::Value::Object(new_content),
    );

    serde_json::Value::Object(val)
}

fn request_json(
    method: &str,
    origin_name: &str,
    origin_key: &SecretKey,
    key_name: &str,
    destination: &str,
    path: &str,
    content: Option<JsonValue>,
) -> String {
    let json_to_sign = RequestJson {
        method: method.to_string(),
        uri: path.to_string(),
        origin: origin_name.to_string(),
        destination: destination.to_string(),
        content,
    };

    let bytes = make_canonical(json_to_sign).expect("Failed make_canonical");
    let signature = sodiumoxide::crypto::sign::ed25519::sign_detached(&bytes, origin_key);
    let base64_signature = base64::encode_config(&signature, base64::STANDARD_NO_PAD);

    format!(
        r#"X-Matrix origin={},key="{}",sig="{}""#,
        origin_name, key_name, base64_signature
    )
}

fn make_canonical(s: impl Serialize) -> Result<Vec<u8>, Error> {
    let value = serde_json::to_value(s)?;
    let uncompact = serde_json::to_vec(&value)?;

    let mut canonical = Vec::with_capacity(uncompact.len());
    indolentjson::compact::compact(&uncompact, &mut canonical).expect("Invalid JSON");

    let canonical = String::from_utf8(canonical).expect("Failed to parse canonical");

    Ok(canonical.into_bytes())
}
