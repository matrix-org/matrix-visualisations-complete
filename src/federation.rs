use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use actix_web::{web, Error, HttpResponse};
use awc::Client;
use chrono::{Duration, Utc};
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
    pub public_key: String,
    pub secret_key: SecretKey,
    pub key_name: String,

    pub connected: Arc<Mutex<bool>>,
    pub join_event: Arc<Mutex<Option<JsonValue>>>,
    pub new_events: Arc<Mutex<Vec<JsonValue>>>,
}

#[derive(Default, Clone, Deserialize, Serialize)]
struct Event {
    room_id: String,       // Room identifier
    sender: String,        // The ID of the user who has sent this event
    origin: String,        // The `server_name` of the homeserver which created this event
    origin_server_ts: i64, // Timestamp in milliseconds on origin homeserver when this event was created
    #[serde(rename = "type")]
    etype: String, // Event type
    state_key: Option<String>, // Indicate whether this event is a state event
    content: JsonValue,    // The content of the event
    prev_events: Vec<JsonValue>, // Event IDs for the most recent events in the room that the homeserver was aware of when it made this event
    pub depth: i64,              // The maximum depth of the `prev_events`, plus one
    auth_events: Vec<JsonValue>, // Event IDs and reference hashes for the authorization events that would allow this event to be in the room
    redacts: Option<String>,     // For redaction events, the ID of the event being redacted
    unsigned: Option<JsonValue>, // Additional data added by the origin server but not covered by the `signatures`
    pub event_id: String,        // The event ID
    hashes: JsonValue, // Content hashes of the PDU, following the algorithm specified in `Signing Events`
    signatures: JsonValue, // Signatures for the PDU, following the algorithm specified in `Signing Events`
}

#[derive(Clone, Deserialize)]
pub struct RequestQuery {
    from: String,
    limit: Option<usize>,
}

#[derive(Clone, Serialize)]
struct ResponseObject {
    events: Vec<Event>,
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

#[derive(Debug, Deserialize, SerDerive)]
struct BackfillResponse {
    origin: String,
    origin_server_ts: usize,
    pdus: Vec<JsonValue>,
}

#[derive(Debug, Deserialize, SerDerive)]
struct ServerKeys {
    server_name: String,
    verify_keys: JsonValue,
    old_verify_keys: JsonValue,
    signatures: JsonValue,
    valid_until_ts: u64,
}

#[derive(Debug, Deserialize, SerDerive)]
pub struct PushRequest {
    origin: String,
    origin_server_ts: u64,
    pdus: Vec<JsonValue>,
    edus: Option<JsonValue>,
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
                    future::Either::B(future::err(actix_web::error::ErrorUnauthorized(
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

pub fn ancestors(
    (room_id, query, fd): (
        web::Path<String>,
        web::Query<RequestQuery>,
        web::Data<FederationData>,
    ),
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let limit = query.limit.map_or(11, |n| n + 1);
    let deepest_events: Vec<String> = query
        .from
        .as_str()
        .split(',')
        .map(|id| id.to_string())
        .collect();
    let v = deepest_events.iter().fold(String::new(), |id, acc| {
        if acc.is_empty() {
            format!("v={}", id)
        } else {
            format!("v={}&v={}", acc, id)
        }
    });

    let client = Client::default();
    let path = format!(
        "/_matrix/federation/v1/backfill/{}?{}&limit={}",
        room_id, v, limit,
    );

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
                    "Error sending /backfill: {}",
                    err
                ))
            })
            .and_then(move |mut response| {
                if response.status().is_success() {
                    future::Either::A(response.json::<BackfillResponse>().limit(1000000).map_err(
                        |err| {
                            actix_web::error::ErrorInternalServerError(format!(
                                "Error making /backfill: {}",
                                err
                            ))
                        },
                    ))
                } else {
                    future::Either::B(future::err(actix_web::error::ErrorUnauthorized(
                        "Unauthorized by the resident HS",
                    )))
                }
            })
            .and_then(move |json| {
                let event_bodies: Vec<Event> = json
                    .pdus
                    .into_iter()
                    .skip(1)
                    .map(|json| {
                        let ev: Event =
                            serde_json::from_value(json).expect("Failed to deserialize Event");

                        ev
                    })
                    .collect();

                let response_object = ResponseObject {
                    events: event_bodies,
                };
                let response_string = serde_json::to_string(&response_object)
                    .expect("Failed to serialize the response object");

                HttpResponse::Ok()
                    .content_type("application/json")
                    .header("Access-Control-Allow-Origin", "*")
                    .header("Access-Control-Allow-Methods", "GET, POST")
                    .header(
                        "Access-Control-Allow-Headers",
                        "Origin, X-Requested-With, Content-Type, Accept",
                    )
                    .body(response_string)
            }),
    )
}

pub fn descendants(
    (_, _, fd): (
        web::Path<String>,
        web::Query<RequestQuery>,
        web::Data<FederationData>,
    ),
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let new_events: Vec<Event> = fd
        .new_events
        .lock()
        .unwrap()
        .drain(..)
        .map(|json| {
            let ev: Event = serde_json::from_value(json).expect("Failed to deserialize Event");

            ev
        })
        .collect();

    let response_object = ResponseObject { events: new_events };
    let response_string =
        serde_json::to_string(&response_object).expect("Failed to serialize the response object");

    Box::new(future::ok(
        HttpResponse::Ok()
            .content_type("application/json")
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST")
            .header(
                "Access-Control-Allow-Headers",
                "Origin, X-Requested-With, Content-Type, Accept",
            )
            .body(response_string),
    ))
}

pub fn serv_cert(
    (_, fd): (web::Path<String>, web::Data<FederationData>),
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let server_name = fd.server_name.clone();
    let key_name = fd.key_name.clone();
    let public_key = fd.public_key.clone();
    let valid_until_ts = (Utc::now() + Duration::days(1)).timestamp_millis() as u64;
    let sig = server_keys_signature(
        &server_name,
        &key_name,
        &public_key,
        valid_until_ts,
        &fd.secret_key,
    );

    let server_keys = ServerKeys {
        server_name,
        verify_keys: json!({
            key_name.clone(): {
                "key": public_key
            }
        }),
        old_verify_keys: json!({}),
        signatures: json!({
            fd.server_name.clone(): {
                key_name: sig
            }
        }),
        valid_until_ts,
    };

    let response_string =
        serde_json::to_string(&server_keys).expect("Failed to serialize the server keys");

    Box::new(futures::future::ok(
        HttpResponse::Ok()
            .content_type("application/json")
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST")
            .header(
                "Access-Control-Allow-Headers",
                "Origin, X-Requested-With, Content-Type, Accept",
            )
            .body(response_string),
    ))
}

pub fn push(
    (_, json, fd): (
        web::Path<String>,
        web::Json<PushRequest>,
        web::Data<FederationData>,
    ),
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let mut new_events = fd.new_events.lock().unwrap();
    let mut new_ids = Vec::new();

    for ev in json.pdus.clone() {
        let id = ev["event_id"].to_string();
        let id = id.trim_matches('"').to_string();
        new_ids.push(id);
        new_events.push(ev);
    }

    let mut ids = HashMap::new();

    for id in new_ids {
        ids.insert(id, json!({}));
    }

    let response_object = json!({ "pdus": ids });

    let response_string =
        serde_json::to_string(&response_object).expect("Failed to serialize the response object");

    Box::new(future::ok(
        HttpResponse::Ok()
            .content_type("application/json")
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST")
            .header(
                "Access-Control-Allow-Headers",
                "Origin, X-Requested-With, Content-Type, Accept",
            )
            .body(response_string),
    ))
}

fn server_keys_signature(
    server_name: &str,
    key_name: &str,
    public_key: &str,
    valid_until_ts: u64,
    signing_key: &SecretKey,
) -> String {
    let obj = json!({
        "server_name": server_name.clone(),
        "verify_keys": { key_name.clone(): { "key": public_key.clone() } },
        "old_verify_keys": {},
        "valid_until_ts": valid_until_ts
    });

    event_signature(&obj, signing_key)
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
