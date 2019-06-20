extern crate actix_web;
extern crate postgres;
extern crate serde_derive;
extern crate serde_json;

use std::sync::Mutex;

use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use postgres::{Connection, TlsMode};
use serde_derive::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

struct Database {
    connection: Connection,
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

fn latest((path, data): (web::Path<String>, web::Data<Mutex<Database>>)) -> impl Responder {
    let db = data.lock().unwrap();

    let deepest_events = get_deepest_events(&path, &db.connection);
    let event_bodies: Vec<_> = deepest_events
        .iter()
        .map(|id| get_json(id, &db.connection).expect("Failed to get event's JSON"))
        .collect();

    if event_bodies.is_empty() {
        HttpResponse::NotFound().body("This room doesn't exist")
    } else {
        HttpResponse::Ok()
            .content_type("application/json")
            .body(serde_json::to_string(&event_bodies).expect("Failed to serialize Event"))
    }
}

fn get_deepest_events(room_id: &str, conn: &Connection) -> Vec<String> {
    let max_depth: i64 = conn
        .query(
            &format!(
                "SELECT MAX(depth) FROM events WHERE room_id = '{}'",
                room_id
            ),
            &[],
        )
        .unwrap()
        .iter()
        .next()
        .expect("Failed to get max_depth")
        .get("max");

    conn.query(
        &format!(
            "SELECT event_id FROM events WHERE room_id = '{}' AND depth = {}",
            room_id, max_depth
        ),
        &[],
    )
    .unwrap()
    .iter()
    .map(|row| row.get("event_id"))
    .collect()
}

fn get_json(id: &str, conn: &Connection) -> Option<JsonValue> {
    let json_str: Option<String> = conn
        .query(
            &format!("SELECT json FROM event_json WHERE event_id = '{}'", id),
            &[],
        )
        .unwrap()
        .iter()
        .next()
        .map(|row| row.get("json"));

    json_str.map(|json_str| serde_json::from_str(&json_str).expect("Failed to deserialize Event"))
}

fn main() -> std::io::Result<()> {
    let connection =
        Connection::connect("postgresql://synapse_user@localhost/synapse", TlsMode::None)
            .expect("Failed to connect to database");

    let db = web::Data::new(Mutex::new(Database { connection }));

    HttpServer::new(move || {
        App::new()
            .register_data(db.clone())
            .service(web::resource("/visualisations/latest/{roomId}").to(latest))
    })
    .bind("127.0.0.1:8088")?
    .run()
}
