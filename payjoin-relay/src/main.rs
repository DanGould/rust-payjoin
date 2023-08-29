use anyhow::Result;
use axum::body::Bytes;
use axum::extract::Path;
use axum::http::StatusCode;
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

    let app = Router::new()
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

    println!("Serverless payjoin relay awaiting HTTP connection on port 8080");
    axum::Server::bind(&"0.0.0.0:8080".parse()?).serve(app.into_make_service()).await?;
    Ok(())
}

fn init_logging() {
    let env_filter =
        EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy();

    tracing_subscriber::fmt().with_target(true).with_level(true).with_env_filter(env_filter).init();

    println!("Logging initialized");
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

async fn get_request(Path(id): Path<String>, pool: DbPool) -> (StatusCode, Vec<u8>) {
    let id = shorten_string(&id);
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
