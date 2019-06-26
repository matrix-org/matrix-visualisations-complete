extern crate actix_web;
extern crate r2d2_postgres;
extern crate serde_derive;
extern crate serde_json;

use std::collections::HashSet;

use actix_web::{guard, web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use r2d2::Pool;
use r2d2_postgres::{PostgresConnectionManager, TlsMode};
use serde_derive::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

struct Database {
    pg_pool: Pool<PostgresConnectionManager>,
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

// Handler for the `/visualisations/deepest/{roomId}` request
fn deepest((path, db): (web::Path<String>, web::Data<Database>)) -> impl Responder {
    if !room_exists(&path, &db.pg_pool) {
        return HttpResponse::NotFound()
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST")
            .header(
                "Access-Control-Allow-Headers",
                "Origin, X-Requested-With, Content-Type, Accept",
            )
            .body("This room doesn't exist");
    }

    let deepest_events = get_deepest_events(&path, &db.pg_pool);
    let event_bodies: Vec<Event> = deepest_events
        .iter()
        .map(|id| {
            let ev: Event = serde_json::from_value(
                get_json(id, &db.pg_pool).expect("Failed to get event's JSON"),
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
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST")
        .header(
            "Access-Control-Allow-Headers",
            "Origin, X-Requested-With, Content-Type, Accept",
        )
        .body(response_string)
}

// Handler for the `/visualisations/ancestors/{roomId}` request
fn ancestors(
    (path, query, db): (
        web::Path<String>,
        web::Query<RequestQuery>,
        web::Data<Database>,
    ),
) -> impl Responder {
    let limit = query.limit.unwrap_or(10);

    if !room_exists(&path, &db.pg_pool) {
        return HttpResponse::NotFound()
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST")
            .header(
                "Access-Control-Allow-Headers",
                "Origin, X-Requested-With, Content-Type, Accept",
            )
            .body("This room doesn't exist");
    }

    // Parse from the query the events from which we will get the ancestors
    let deepest_events: Vec<String> = query
        .from
        .as_str()
        .split(',')
        .map(|id| id.to_string())
        .collect();

    let ancestor_events = get_ancestor_events(&path, &db.pg_pool, &deepest_events, limit);
    let event_bodies: Vec<Event> = ancestor_events
        .iter()
        .map(|id| {
            let ev: Event = serde_json::from_value(
                get_json(id, &db.pg_pool).expect("Failed to get event's JSON"),
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
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST")
        .header(
            "Access-Control-Allow-Headers",
            "Origin, X-Requested-With, Content-Type, Accept",
        )
        .body(response_string)
}

// Handler for the `/visualisations/descendants/{roomId}` request
fn descendants(
    (path, query, db): (
        web::Path<String>,
        web::Query<RequestQuery>,
        web::Data<Database>,
    ),
) -> impl Responder {
    let limit = query.limit.unwrap_or(10);

    if !room_exists(&path, &db.pg_pool) {
        return HttpResponse::NotFound()
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST")
            .header(
                "Access-Control-Allow-Headers",
                "Origin, X-Requested-With, Content-Type, Accept",
            )
            .body("This room doesn't exist");
    }

    // Parse from the query the events from which we will get the descendants
    let highest_events: Vec<String> = query
        .from
        .as_str()
        .split(',')
        .map(|id| id.to_string())
        .collect();

    let descendant_events = get_descendants_events(&path, &db.pg_pool, &highest_events, limit);
    let event_bodies: Vec<Event> = descendant_events
        .iter()
        .map(|id| {
            let ev: Event = serde_json::from_value(
                get_json(id, &db.pg_pool).expect("Failed to get event's JSON"),
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
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST")
        .header(
            "Access-Control-Allow-Headers",
            "Origin, X-Requested-With, Content-Type, Accept",
        )
        .body(response_string)
}

// Makes a request to the database to check whether the room `room_id` exists
fn room_exists(room_id: &str, pg_pool: &Pool<PostgresConnectionManager>) -> bool {
    let pool = pg_pool.clone();
    let client = pool.get().unwrap();

    let nb_ev = client
        .query("SELECT * FROM events WHERE room_id = $1", &[&room_id])
        .unwrap()
        .len();

    nb_ev > 0
}

// Makes requests to the database to get the events with the greatest depth of the room `room_id`
fn get_deepest_events(room_id: &str, pg_pool: &Pool<PostgresConnectionManager>) -> Vec<String> {
    let pool = pg_pool.clone();
    let client = pool.get().unwrap();

    let max_depth: i64 = client
        .query(
            "SELECT MAX(depth) FROM events WHERE room_id = $1",
            &[&room_id],
        )
        .unwrap()
        .iter()
        .next()
        .expect("Failed to get max_depth")
        .get("max");

    client
        .query(
            "SELECT event_id FROM events WHERE room_id = $1 AND depth = $2",
            &[&room_id, &max_depth],
        )
        .unwrap()
        .iter()
        .map(|row| row.get("event_id"))
        .collect()
}

// Makes requests to the database to get `limit` ancestors of a set `deepest_events` of events
fn get_ancestor_events(
    room_id: &str,
    pg_pool: &Pool<PostgresConnectionManager>,
    deepest_events: &Vec<String>,
    limit: usize,
) -> HashSet<String> {
    let mut seen_events: HashSet<String> = HashSet::new();
    let mut front: HashSet<String> = deepest_events.iter().cloned().collect();
    let mut event_results: HashSet<String> = HashSet::new();

    while !front.is_empty() && event_results.len() < limit {
        let mut new_front: HashSet<String> = HashSet::new();

        for event_id in front.iter() {
            let pool = pg_pool.clone();
            let client = pool.get().unwrap();

            let query_limit = limit - event_results.len();

            let new_results: HashSet<String> = client
                .query(
                    "SELECT prev_event_id FROM event_edges WHERE room_id = $1 AND event_id = $2 AND is_state = False LIMIT $3",
                    &[&room_id, &event_id, &(query_limit as i64)],
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

// Makes requests to the database to get `limit` descendants of a set `highest_events` of events
fn get_descendants_events(
    room_id: &str,
    pg_pool: &Pool<PostgresConnectionManager>,
    highest_events: &Vec<String>,
    limit: usize,
) -> HashSet<String> {
    let mut seen_events: HashSet<String> = HashSet::new();
    let mut front: HashSet<String> = highest_events.iter().cloned().collect();
    let mut event_results: HashSet<String> = HashSet::new();

    while !front.is_empty() && event_results.len() < limit {
        let mut new_front: HashSet<String> = HashSet::new();

        for event_id in front.iter() {
            let pool = pg_pool.clone();
            let client = pool.get().unwrap();

            let query_limit = limit - event_results.len();

            let new_results: HashSet<String> = client
                .query(
                    "SELECT event_id FROM event_edges WHERE room_id = $1 AND prev_event_id = $2 AND is_state = False LIMIT $3",
                    &[&room_id, &event_id, &(query_limit as i64)],
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

// Makes a request to the database to get the JSON body of the event `id`
fn get_json(id: &str, pg_pool: &Pool<PostgresConnectionManager>) -> Option<JsonValue> {
    let pool = pg_pool.clone();
    let client = pool.get().unwrap();

    let json_str: Option<String> = client
        .query("SELECT json FROM event_json WHERE event_id = $1", &[&id])
        .unwrap()
        .iter()
        .next()
        .map(|row| row.get("json"));

    json_str.map(|json_str| serde_json::from_str(&json_str).expect("Failed to deserialize Event"))
}

fn main() -> std::io::Result<()> {
    let manager =
        PostgresConnectionManager::new("postgres://synapse_user@localhost/synapse", TlsMode::None)
            .unwrap();
    let pg_pool = r2d2::Pool::new(manager).expect("Failed to create pool");

    let db = web::Data::new(Database { pg_pool });

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
            .service(web::resource("/visualisations/deepest/{roomId}").to(deepest))
            .service(web::resource("/visualisations/ancestors/{roomId}").to(ancestors))
            .service(web::resource("/visualisations/descendants/{roomId}").to(descendants))
    })
    .bind("127.0.0.1:8088")?
    .run()
}
