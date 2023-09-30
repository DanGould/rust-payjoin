use std::sync::Arc;

use anyhow::{Context, Result};
use axum::body::Bytes;
use axum::extract::Path;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use payjoin::v2::MAX_BUFFER_SIZE;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

mod db;
use crate::db::DbPool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();
    let pool = DbPool::new(std::time::Duration::from_secs(30)).await?;
    let ohttp = Arc::new(init_ohttp()?);
    let ohttp_config = ohttp_config(&*ohttp)?;
    let target_resource = Router::new()
        .route(
            "/:id",
            post({
                let pool = pool.clone();
                move |id, body| post_fallback(id, body, pool)
            }),
        )
        .route(
            "/:id/receive",
            get({
                let pool = pool.clone();
                move |id| get_request(id, pool)
            })
            .post({
                let pool = pool.clone();
                move |id, body| post_payjoin(id, body, pool)
            }),
        );

    let ohttp_gateway = Router::new()
        .route("/", post(move |body| handle_ohttp(body, target_resource, ohttp)))
        .route("/ohttp-keys", get(move || get_ohttp_config(ohttp_config)));

    println!("Serverless payjoin relay awaiting HTTP connection on port 8080");
    axum::Server::bind(&"0.0.0.0:8080".parse()?).serve(ohttp_gateway.into_make_service()).await?;
    //hyper::Server::bind(&"0.0.0.0:8080").serve()
    Ok(())
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
    let b64_config = payjoin::bitcoin::base64::encode_config(
        &encoded_config,
        payjoin::bitcoin::base64::Config::new(
            payjoin::bitcoin::base64::CharacterSet::UrlSafe,
            false,
        ),
    );
    tracing::info!("ohttp server config base64 UrlSafe: {:?}", b64_config);
    ohttp::Server::new(server_config).with_context(|| "Failed to initialize ohttp server")
}

async fn handle_ohttp(
    enc_request: Bytes,
    target: Router,
    ohttp: Arc<ohttp::Server>,
) -> (StatusCode, Vec<u8>) {
    match handle_ohttp_inner(enc_request, target, ohttp).await {
        Ok(res) => res,
        Err(e) => {
            tracing::error!("ohttp error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, vec![])
        }
    }
}

async fn handle_ohttp_inner(
    enc_request: Bytes,
    mut target: Router,
    ohttp: Arc<ohttp::Server>,
) -> Result<(StatusCode, Vec<u8>)> {
    use axum::body::Body;
    use http::Uri;
    use tower_service::Service;

    let (bhttp_req, res_ctx) = ohttp.decapsulate(&enc_request)?;
    let mut cursor = std::io::Cursor::new(bhttp_req);
    let req = bhttp::Message::read_bhttp(&mut cursor)?;
    let uri = Uri::builder()
        .scheme(req.control().scheme().unwrap_or_default())
        .authority(req.control().authority().unwrap_or_default())
        .path_and_query(req.control().path().unwrap_or_default())
        .build()?;
    let body = req.content().to_vec();
    let mut request =
        Request::builder().uri(uri).method(req.control().method().unwrap_or_default());
    for header in req.header().fields() {
        request = request.header(header.name(), header.value())
    }
    let request = request.body(Body::from(body))?;

    let response = target.call(request).await?;

    let (parts, body) = response.into_parts();
    let mut bhttp_res = bhttp::Message::response(parts.status.as_u16());
    let full_body = hyper::body::to_bytes(body).await?;
    bhttp_res.write_content(&full_body);
    let mut bhttp_bytes = Vec::new();
    bhttp_res.write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_bytes)?;
    let ohttp_res = res_ctx.encapsulate(&bhttp_bytes)?;
    Ok((StatusCode::OK, ohttp_res))
}

fn ohttp_config(server: &ohttp::Server) -> Result<String> {
    use payjoin::bitcoin::base64;

    let b64_config = base64::Config::new(base64::CharacterSet::UrlSafe, false);
    let encoded_config =
        server.config().encode().with_context(|| "Failed to encode ohttp config")?;
    Ok(base64::encode_config(&encoded_config, b64_config))
}

async fn post_fallback(Path(id): Path<String>, body: Bytes, pool: DbPool) -> (StatusCode, Vec<u8>) {
    let id = shorten_string(&id);
    let body = body.to_vec();
    let body_len = body.len();
    if body_len > MAX_BUFFER_SIZE {
        return (StatusCode::PAYLOAD_TOO_LARGE, b"Payload too large".to_vec());
    }
    match pool.push_req(&id, body).await {
        Ok(_) => (),
        Err(_) => return (StatusCode::BAD_REQUEST, "Bad request".as_bytes().to_vec()),
    };
    match pool.peek_res(&id).await {
        Some(res) => match res {
            Ok(buffered_res) => (StatusCode::OK, buffered_res),
            Err(_) => (StatusCode::BAD_REQUEST, vec![]),
        },
        None => (StatusCode::ACCEPTED, vec![]),
    }
}

async fn get_ohttp_config(config: String) -> (StatusCode, String) { (StatusCode::OK, config) }

async fn get_request(Path(id): Path<String>, pool: DbPool) -> (StatusCode, Vec<u8>) {
    let id = shorten_string(&id);
    tracing::debug!("peek request for id: {}", id);
    match pool.peek_req(&id).await {
        Some(res) => match res {
            Ok(buffered_req) => (StatusCode::OK, buffered_req),
            Err(_) => (StatusCode::BAD_REQUEST, vec![]),
        },
        None => (StatusCode::ACCEPTED, vec![]),
    }
}

async fn post_payjoin(Path(id): Path<String>, res: Bytes, pool: DbPool) -> (StatusCode, String) {
    let id = shorten_string(&id);
    match pool.push_res(&id, res.to_vec()).await {
        Ok(_) => (StatusCode::OK, "Received".to_string()),
        Err(_) => (StatusCode::BAD_REQUEST, "Bad request".to_string()),
    }
}

fn shorten_string(input: &str) -> String { input.chars().take(8).collect() }
