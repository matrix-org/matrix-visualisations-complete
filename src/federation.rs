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

    let bytes = make_canonical(json_to_sign).expect("Failed make_compact");
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
