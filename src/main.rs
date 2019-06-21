extern crate actix_web;
extern crate postgres;
extern crate serde_derive;
extern crate serde_json;

use std::collections::HashSet;
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

#[derive(Clone, Deserialize)]
struct RequestQuery {
    from: String,
    limit: Option<usize>,
}

#[derive(Clone, Serialize)]
struct ResponseObject {
    events: Vec<Event>,
}

fn deepest((path, data): (web::Path<String>, web::Data<Mutex<Database>>)) -> impl Responder {
    let db = data.lock().unwrap();

    if !room_exists(&path, &db.connection) {
        return HttpResponse::NotFound().body("This room doesn't exist");
    }

    let deepest_events = get_deepest_events(&path, &db.connection);
    let event_bodies: Vec<Event> = deepest_events
        .iter()
        .map(|id| {
            let ev: Event = serde_json::from_value(
                get_json(id, &db.connection).expect("Failed to get event's JSON"),
            )
            .expect("Failed to deserialize Event");

            ev
        })
        .collect();

    let response_object = ResponseObject {
        events: event_bodies,
    };
    let response_string =
        serde_json::to_string(&response_object).expect("Failed to serialize the response object");

    HttpResponse::Ok()
        .content_type("application/json")
        .body(response_string)
}

fn ancestors(
    (path, query, data): (
        web::Path<String>,
        web::Query<RequestQuery>,
        web::Data<Mutex<Database>>,
    ),
) -> impl Responder {
    let db = data.lock().unwrap();
    let limit = query.limit.unwrap_or(10);

    if !room_exists(&path, &db.connection) {
        return HttpResponse::NotFound().body("This room doesn't exist");
    }

    let deepest_events: Vec<String> = query
        .from
        .as_str()
        .split(',')
        .map(|id| id.to_string())
        .collect();

    let ancestor_events = get_ancestor_events(&path, &db.connection, &deepest_events, limit);
    let event_bodies: Vec<Event> = ancestor_events
        .iter()
        .map(|id| {
            let ev: Event = serde_json::from_value(
                get_json(id, &db.connection).expect("Failed to get event's JSON"),
            )
            .expect("Failed to deserialize Event");

            ev
        })
        .collect();

    let response_object = ResponseObject {
        events: event_bodies,
    };
    let response_string =
        serde_json::to_string(&response_object).expect("Failed to serialize the response object");

    HttpResponse::Ok()
        .content_type("application/json")
        .body(response_string)
}

fn descendants(
    (path, query, data): (
        web::Path<String>,
        web::Query<RequestQuery>,
        web::Data<Mutex<Database>>,
    ),
) -> impl Responder {
    let db = data.lock().unwrap();
    let limit = query.limit.unwrap_or(10);

    if !room_exists(&path, &db.connection) {
        return HttpResponse::NotFound().body("This room doesn't exist");
    }

    let highest_events: Vec<String> = query
        .from
        .as_str()
        .split(',')
        .map(|id| id.to_string())
        .collect();

    let descendant_events = get_descendants_events(&path, &db.connection, &highest_events, limit);
    let event_bodies: Vec<Event> = descendant_events
        .iter()
        .map(|id| {
            let ev: Event = serde_json::from_value(
                get_json(id, &db.connection).expect("Failed to get event's JSON"),
            )
            .expect("Failed to deserialize Event");

            ev
        })
        .collect();

    let response_object = ResponseObject {
        events: event_bodies,
    };
    let response_string =
        serde_json::to_string(&response_object).expect("Failed to serialize the response object");

    HttpResponse::Ok()
        .content_type("application/json")
        .body(response_string)
}

fn room_exists(room_id: &str, conn: &Connection) -> bool {
    let nb_ev = conn
        .query(
            &format!("SELECT * FROM events WHERE room_id = '{}'", room_id),
            &[],
        )
        .unwrap()
        .iter()
        .count();

    nb_ev > 0
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

fn get_ancestor_events(
    room_id: &str,
    conn: &Connection,
    deepest_events: &Vec<String>,
    limit: usize,
) -> HashSet<String> {
    let mut seen_events: HashSet<String> = HashSet::new();
    let mut front: HashSet<String> = deepest_events.iter().cloned().collect();
    let mut event_results: HashSet<String> = HashSet::new();

    while !front.is_empty() && event_results.len() < limit {
        let mut new_front: HashSet<String> = HashSet::new();

        for event_id in front.iter() {
            let new_results: HashSet<String> = conn
                .query(
                    &format!(
                        "SELECT prev_event_id FROM event_edges WHERE room_id = '{}' AND event_id = '{}' AND is_state = False LIMIT {}",
                        room_id, event_id, limit - event_results.len(),
                    ),
                    &[],
                )
                .unwrap()
                .iter()
                .map(|row| row.get("prev_event_id"))
                .filter(|id| !seen_events.contains(id))
                .collect();

            new_results.iter().for_each(|id| {
                new_front.insert(id.to_string());
                seen_events.insert(id.to_string());
                event_results.insert(id.to_string());
            });
        }

        front = new_front;
    }

    event_results
}

fn get_descendants_events(
    room_id: &str,
    conn: &Connection,
    highest_events: &Vec<String>,
    limit: usize,
) -> HashSet<String> {
    let mut seen_events: HashSet<String> = HashSet::new();
    let mut front: HashSet<String> = highest_events.iter().cloned().collect();
    let mut event_results: HashSet<String> = HashSet::new();

    while !front.is_empty() && event_results.len() < limit {
        let mut new_front: HashSet<String> = HashSet::new();

        for event_id in front.iter() {
            let new_results: HashSet<String> = conn
                .query(
                    &format!(
                        "SELECT event_id FROM event_edges WHERE room_id = '{}' AND prev_event_id = '{}' AND is_state = False LIMIT {}",
                        room_id, event_id, limit - event_results.len(),
                    ),
                    &[],
                )
                .unwrap()
                .iter()
                .map(|row| row.get("event_id"))
                .filter(|id| !seen_events.contains(id))
                .collect();

            new_results.iter().for_each(|id| {
                new_front.insert(id.to_string());
                seen_events.insert(id.to_string());
                event_results.insert(id.to_string());
            });
        }

        front = new_front;
    }

    event_results
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
            .service(web::resource("/visualisations/deepest/{roomId}").to(deepest))
            .service(web::resource("/visualisations/ancestors/{roomId}").to(ancestors))
            .service(web::resource("/visualisations/descendants/{roomId}").to(descendants))
    })
    .bind("127.0.0.1:8088")?
    .run()
}
