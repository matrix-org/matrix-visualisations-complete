use std::collections::HashSet;

use actix_web::{web, Error, HttpResponse};
use futures::future;
use futures::Future;
use futures_cpupool::CpuPool;
use r2d2::Pool;
use r2d2_postgres::postgres::error::Error as PgError;
use r2d2_postgres::PostgresConnectionManager;
use serde_derive::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

pub struct Database {
    pub cpu_pool: CpuPool,
    pub pg_pool: Pool<PostgresConnectionManager>,
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

// Handler for the `/visualisations/deepest/{roomId}` request
pub fn deepest(
    (path, db): (web::Path<String>, web::Data<Database>),
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    if !room_exists(&path, &db.pg_pool) {
        return Box::new(futures::future::ok(
            HttpResponse::NotFound()
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "GET, POST")
                .header(
                    "Access-Control-Allow-Headers",
                    "Origin, X-Requested-With, Content-Type, Accept",
                )
                .body("This room doesn't exist"),
        ));
    }

    Box::new(get_deepest_events(&path, &db.cpu_pool, &db.pg_pool).then(
        move |result| match result {
            Ok(deepest_events) => {
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
            }
            Err(_) => {
                return HttpResponse::InternalServerError()
                    .header("Access-Control-Allow-Origin", "*")
                    .header("Access-Control-Allow-Methods", "GET, POST")
                    .header(
                        "Access-Control-Allow-Headers",
                        "Origin, X-Requested-With, Content-Type, Accept",
                    )
                    .body("Error with the database");
            }
        },
    ))
}

// Handler for the `/visualisations/ancestors/{roomId}` request
pub fn ancestors(
    (path, query, db): (
        web::Path<String>,
        web::Query<RequestQuery>,
        web::Data<Database>,
    ),
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let limit = query.limit.unwrap_or(10);

    if !room_exists(&path, &db.pg_pool) {
        return Box::new(futures::future::ok(
            HttpResponse::NotFound()
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "GET, POST")
                .header(
                    "Access-Control-Allow-Headers",
                    "Origin, X-Requested-With, Content-Type, Accept",
                )
                .body("This room doesn't exist"),
        ));
    }

    // Parse from the query the events from which we will get the ancestors
    let deepest_events: Vec<String> = query
        .from
        .as_str()
        .split(',')
        .map(|id| id.to_string())
        .collect();

    Box::new(
        get_ancestor_events(&path, &db.cpu_pool, &db.pg_pool, &deepest_events, limit).then(
            move |result| match result {
                Ok(ancestor_events) => {
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
                }
                Err(_) => {
                    return HttpResponse::InternalServerError()
                        .header("Access-Control-Allow-Origin", "*")
                        .header("Access-Control-Allow-Methods", "GET, POST")
                        .header(
                            "Access-Control-Allow-Headers",
                            "Origin, X-Requested-With, Content-Type, Accept",
                        )
                        .body("Error with the database");
                }
            },
        ),
    )
}

// Handler for the `/visualisations/descendants/{roomId}` request
pub fn descendants(
    (path, query, db): (
        web::Path<String>,
        web::Query<RequestQuery>,
        web::Data<Database>,
    ),
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let limit = query.limit.unwrap_or(10);

    if !room_exists(&path, &db.pg_pool) {
        return Box::new(futures::future::ok(
            HttpResponse::NotFound()
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "GET, POST")
                .header(
                    "Access-Control-Allow-Headers",
                    "Origin, X-Requested-With, Content-Type, Accept",
                )
                .body("This room doesn't exist"),
        ));
    }

    // Parse from the query the events from which we will get the descendants
    let highest_events: Vec<String> = query
        .from
        .as_str()
        .split(',')
        .map(|id| id.to_string())
        .collect();

    Box::new(
        get_descendants_events(&path, &db.cpu_pool, &db.pg_pool, &highest_events, limit).then(
            move |result| match result {
                Ok(descendant_events) => {
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
                }
                Err(_) => {
                    return HttpResponse::InternalServerError()
                        .header("Access-Control-Allow-Origin", "*")
                        .header("Access-Control-Allow-Methods", "GET, POST")
                        .header(
                            "Access-Control-Allow-Headers",
                            "Origin, X-Requested-With, Content-Type, Accept",
                        )
                        .body("Error with the database");
                }
            },
        ),
    )
}

pub fn state(
    (path, query, db): (
        web::Path<String>,
        web::Query<RequestQuery>,
        web::Data<Database>,
    ),
) -> Box<dyn Future<Item = HttpResponse, Error = Error>> {
    let from_event = &query.from;
    let db_clone = db.clone();

    if !room_exists(&path, &db.pg_pool) {
        return Box::new(futures::future::ok(
            HttpResponse::NotFound()
                .header("Access-Control-Allow-Origin", "*")
                .header("Access-Control-Allow-Methods", "GET, POST")
                .header(
                    "Access-Control-Allow-Headers",
                    "Origin, X-Requested-With, Content-Type, Accept",
                )
                .body("This room doesn't exist"),
        ));
    }

    Box::new(
        get_state_group(&db.cpu_pool, &db.pg_pool, from_event)
            .map_err(|err| {
                actix_web::error::ErrorInternalServerError(format!(
                    "Error with the database: {}",
                    err
                ))
            })
            .and_then(move |state_group| match state_group {
                Some(sg) => future::Either::A(
                    get_state_event_ids(&db_clone.cpu_pool, &db_clone.pg_pool, sg).map_err(|err| {
                        actix_web::error::ErrorInternalServerError(format!(
                            "Error with the database: {}",
                            err
                        ))
                    }),
                ),
                None => future::Either::B(future::err(actix_web::error::ErrorNotFound(
                    "There is no such event",
                ))),
            })
            .and_then(move |event_ids| {
                let event_bodies: Vec<Event> = event_ids
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
            }),
    )
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
fn get_deepest_events(
    room_id: &str,
    cpu_pool: &CpuPool,
    pg_pool: &Pool<PostgresConnectionManager>,
) -> impl Future<Item = Vec<String>, Error = PgError> {
    let room_id = room_id.to_string();
    let pool = pg_pool.clone();

    let f = cpu_pool.spawn_fn(move || -> Result<_, PgError> {
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

        Ok(client
            .query(
                "SELECT event_id FROM events WHERE room_id = $1 AND depth = $2",
                &[&room_id, &max_depth],
            )
            .unwrap()
            .iter()
            .map(|row| row.get("event_id"))
            .collect())
    });

    f
}

// Makes requests to the database to get `limit` ancestors of a set `deepest_events` of events
fn get_ancestor_events(
    room_id: &str,
    cpu_pool: &CpuPool,
    pg_pool: &Pool<PostgresConnectionManager>,
    deepest_events: &Vec<String>,
    limit: usize,
) -> impl Future<Item = HashSet<String>, Error = PgError> {
    let room_id = room_id.to_string();
    let pool = pg_pool.clone();
    let deepest_events = deepest_events.clone();

    let f = cpu_pool.spawn_fn(move || -> Result<_, PgError> {
        let mut seen_events: HashSet<String> = HashSet::new();
        let mut front: HashSet<String> = deepest_events.iter().cloned().collect();
        let mut event_results: HashSet<String> = HashSet::new();

        while !front.is_empty() && event_results.len() < limit {
            let mut new_front: HashSet<String> = HashSet::new();

            for event_id in front.iter() {
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

        Ok(event_results)
    });

    f
}

// Makes requests to the database to get `limit` descendants of a set `highest_events` of events
fn get_descendants_events(
    room_id: &str,
    cpu_pool: &CpuPool,
    pg_pool: &Pool<PostgresConnectionManager>,
    highest_events: &Vec<String>,
    limit: usize,
) -> impl Future<Item = HashSet<String>, Error = PgError> {
    let room_id = room_id.to_string();
    let pool = pg_pool.clone();
    let highest_events = highest_events.clone();

    let f = cpu_pool.spawn_fn(move || -> Result<_, PgError> {
        let mut seen_events: HashSet<String> = HashSet::new();
        let mut front: HashSet<String> = highest_events.iter().cloned().collect();
        let mut event_results: HashSet<String> = HashSet::new();

        while !front.is_empty() && event_results.len() < limit {
            let mut new_front: HashSet<String> = HashSet::new();

            for event_id in front.iter() {
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

        Ok(event_results)
    });

    f
}

fn get_state_group(
    cpu_pool: &CpuPool,
    pg_pool: &Pool<PostgresConnectionManager>,
    event: &str,
) -> impl Future<Item = Option<i64>, Error = PgError> {
    let pool = pg_pool.clone();
    let event = event.to_string();

    let f = cpu_pool.spawn_fn(move || -> Result<_, PgError> {
        let client = pool.get().unwrap();

        let state_group: Option<i64> = client
            .query(
                "SELECT state_group FROM event_to_state_groups WHERE event_id = $1",
                &[&event],
            )
            .unwrap()
            .iter()
            .next()
            .map(|row| row.get("state_group"));

        Ok(state_group)
    });

    f
}

fn get_state_event_ids(
    cpu_pool: &CpuPool,
    pg_pool: &Pool<PostgresConnectionManager>,
    state_group: i64,
) -> impl Future<Item = Vec<String>, Error = PgError> {
    let pool = pg_pool.clone();

    let f = cpu_pool.spawn_fn(move || -> Result<_, PgError> {
        let client = pool.get().unwrap();

        let event_ids: Vec<String> = client
            .query(
                "WITH RECURSIVE state(state_group) AS (
                    VALUES($1::bigint)
                    UNION ALL
                    SELECT prev_state_group FROM state_group_edges e, state s
                    WHERE s.state_group = e.state_group
                )
                SELECT DISTINCT type, state_key, last_value(event_id) OVER (
                    PARTITION BY type, state_key ORDER BY state_group ASC
                    ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING
                ) AS event_id FROM state_groups_state
                WHERE state_group IN (
                    SELECT state_group FROM state
                )",
                &[&state_group],
            )
            .unwrap()
            .iter()
            .map(|row| row.get("event_id"))
            .collect();

        Ok(event_ids)
    });

    f
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
