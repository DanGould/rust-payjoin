use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, StatusCode, Uri};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

const MAX_BUFFER_SIZE: usize = 65536;

mod db;
use crate::db::DbPool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();

    let pool = DbPool::new(std::time::Duration::from_secs(30)).await?;
    let ohttp = Arc::new(init_ohttp()?);
    let make_svc = make_service_fn(|_| {
        let pool = pool.clone();
        let ohttp = ohttp.clone();
        async move {
            let handler = move |req| handle_ohttp_gateway(req, pool.clone(), ohttp.clone());
            Ok::<_, hyper::Error>(service_fn(handler))
        }
    });
    let bind_addr: SocketAddr = "0.0.0.0:8080".parse().expect("Invalid bind address");
    let server = hyper::Server::bind(&bind_addr).serve(make_svc);
    println!("Serverless payjoin relay awaiting HTTP connection on port 8080");
    Ok(server.await?)
}

fn init_logging() {
    let env_filter =
        EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy();

    tracing_subscriber::fmt().with_target(true).with_level(true).with_env_filter(env_filter).init();

    println!("Logging initialized");
}

fn init_ohttp() -> Result<ohttp::Server> {
    use ohttp::hpke::{Aead, Kdf, Kem};
    use ohttp::{KeyId, SymmetricSuite};

    const KEY_ID: KeyId = 1;
    const KEM: Kem = Kem::X25519Sha256;
    const SYMMETRIC: &[SymmetricSuite] =
        &[SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];

    // create or read from file
    let server_config = ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC))?;
    let encoded_config = server_config.encode()?;
    let b64_config = base64::encode_config(
        &encoded_config,
        base64::Config::new(
            base64::CharacterSet::UrlSafe,
            false,
        ),
    );
    tracing::info!("ohttp server config base64 UrlSafe: {:?}", b64_config);
    Ok(ohttp::Server::new(server_config)?)
}

async fn handle_ohttp_gateway(
    req: Request<Body>,
    pool: DbPool,
    ohttp: Arc<ohttp::Server>,
) -> Result<Response<Body>> {
    let mut response = match (req.method(), req.uri().path()) {
        (&Method::POST, "/") => handle_ohttp(req.into_body(), pool, ohttp).await,
        (&Method::GET, "/ohttp-config") => Ok(get_ohttp_config(ohttp_config(&ohttp)?).await),
        _ => Ok(not_found()),
    }
    .unwrap_or_else(|e| e.to_response());

    // Allow CORS for third-party access
    response
        .headers_mut()
        .insert("Access-Control-Allow-Origin", hyper::header::HeaderValue::from_static("*"));

    Ok(response)
}

async fn handle_ohttp(
    body: Body,
    pool: DbPool,
    ohttp: Arc<ohttp::Server>,
) -> Result<Response<Body>, HandlerError> {
    // decapsulate
    let ohttp_body =
        hyper::body::to_bytes(body).await.map_err(|e| HandlerError::BadRequest(e.into()))?;

    let (bhttp_req, res_ctx) = ohttp.decapsulate(&ohttp_body).map_err(|e| HandlerError::BadRequest(e.into()))?;
    let mut cursor = std::io::Cursor::new(bhttp_req);
    let req = bhttp::Message::read_bhttp(&mut cursor).map_err(|e| HandlerError::BadRequest(e.into()))?;
    let uri = Uri::builder()
        .scheme(req.control().scheme().unwrap_or_default())
        .authority(req.control().authority().unwrap_or_default())
        .path_and_query(req.control().path().unwrap_or_default())
        .build()?;
    let body = req.content().to_vec();
    let mut http_req = Request::builder().uri(uri).method(req.control().method().unwrap_or_default());
    for header in req.header().fields() {
        http_req = http_req.header(header.name(), header.value())
    }
    let request = http_req.body(Body::from(body))?;

    let response = handle_http(pool, request).await?;

    let (parts, body) = response.into_parts();
    let mut bhttp_res = bhttp::Message::response(parts.status.as_u16());
    let full_body = hyper::body::to_bytes(body).await.map_err(|e| HandlerError::InternalServerError(e.into()))?;
    bhttp_res.write_content(&full_body);
    let mut bhttp_bytes = Vec::new();
    bhttp_res.write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_bytes).map_err(|e| HandlerError::InternalServerError(e.into()))?;
    let ohttp_res = res_ctx.encapsulate(&bhttp_bytes).map_err(|e| HandlerError::InternalServerError(e.into()))?;
    Ok(Response::new(Body::from(ohttp_res)))
}

async fn handle_http(pool: DbPool, req: Request<Body>) -> Result<Response<Body>, HandlerError> {
    let path = req.uri().path().to_string();
    let (parts, body) = req.into_parts();

    let path_segments: Vec<&str> = path.split('/').collect();
    dbg!(&path_segments);
    match (parts.method, path_segments.as_slice()) {
        (Method::POST, &["", id]) => post_fallback(id, body, pool).await,
        (Method::GET, &["", id, "receive"]) => get_request(id, pool).await,
        (Method::POST, &["", id, "receive"]) => post_payjoin(id, body, pool).await,
        _ => Ok(not_found()),
    }
}

enum HandlerError {
    PayloadTooLarge,
    InternalServerError(Box<dyn std::error::Error>),
    BadRequest(Box<dyn std::error::Error>),
}

impl HandlerError {
    fn to_response(&self) -> Response<Body> {
        let status = match self {
            HandlerError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::InternalServerError(e) => {
                tracing::error!("Internal server error: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::BadRequest(e) => {
                tracing::error!("Bad request: {}", e);
                StatusCode::BAD_REQUEST
            },
        };

        let mut res = Response::default();
        *res.status_mut() = status;
        res
    }
}

impl From<hyper::http::Error> for HandlerError {
    fn from(e: hyper::http::Error) -> Self { HandlerError::InternalServerError(e.into()) }
}

async fn post_fallback(id: &str, body: Body, pool: DbPool) -> Result<Response<Body>, HandlerError> {
    let id = shorten_string(id);
    let req = hyper::body::to_bytes(body).await.map_err(|e| HandlerError::InternalServerError(e.into()))?;

    if req.len() > MAX_BUFFER_SIZE {
        return Err(HandlerError::PayloadTooLarge);
    }

    match pool.push_req(&id, req.into()).await {
        Ok(_) => (),
        Err(e) => return Err(HandlerError::BadRequest(e.into())),
    };

    match pool.peek_res(&id).await {
        Some(result) => match result {
            Ok(buffered_res) => Ok(Response::new(Body::from(buffered_res))),
            Err(e) => Err(HandlerError::BadRequest(e.into())),
        },
        None => Ok(Response::builder().status(StatusCode::ACCEPTED).body(Body::empty())?),
    }
}

async fn get_request(id: &str, pool: DbPool) -> Result<Response<Body>, HandlerError> {
    let id = shorten_string(id);
    match pool.peek_req(&id).await {
        Some(result) => match result {
            Ok(buffered_req) => Ok(Response::new(Body::from(buffered_req))),
            Err(e) => Err(HandlerError::BadRequest(e.into())),
        },
        None => Ok(Response::builder().status(StatusCode::ACCEPTED).body(Body::empty())?),
    }
}

async fn post_payjoin(id: &str, body: Body, pool: DbPool) -> Result<Response<Body>, HandlerError> {
    let id = shorten_string(id);
    let res = hyper::body::to_bytes(body).await.map_err(|e| HandlerError::InternalServerError(e.into()))?;

    match pool.push_res(&id, res.into()).await {
        Ok(_) => Ok(Response::builder().status(StatusCode::NO_CONTENT).body(Body::empty())?),
        Err(e) => Err(HandlerError::BadRequest(e.into())),
    }
}

fn not_found() -> Response<Body> {
    let mut res = Response::default();
    *res.status_mut() = StatusCode::NOT_FOUND;
    res
}

async fn get_ohttp_config(config: String) -> Response<Body> {
    let mut res = Response::default();
    *res.body_mut() = Body::from(config);
    res
}

fn shorten_string(input: &str) -> String { input.chars().take(8).collect() }

fn ohttp_config(server: &ohttp::Server) -> Result<String> {
    let b64_config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
    let encoded_config = server.config().encode()?;
    Ok(base64::encode_config(encoded_config, b64_config))
}
