use std::net::SocketAddr;

use anyhow::Result;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, StatusCode};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

const MAX_BUFFER_SIZE: usize = 65536;

mod db;
use crate::db::DbPool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();

    let pool = DbPool::new(std::time::Duration::from_secs(30)).await?;
    let make_svc = make_service_fn(|_| {
        let pool = pool.clone();
        async move {
            let handler = move |req| handle_web_req(pool.clone(), req);
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

async fn handle_web_req(pool: DbPool, req: Request<Body>) -> Result<Response<Body>> {
    let path = req.uri().path().to_string();
    let (parts, body) = req.into_parts();

    let path_segments: Vec<&str> = path.split('/').collect();
    dbg!(&path_segments);
    let mut response = match (parts.method, path_segments.as_slice()) {
        (Method::POST, &["", id]) => post_fallback(id, body, pool).await,
        (Method::GET, &["", id, "receive"]) => get_request(id, pool).await,
        (Method::POST, &["", id, "receive"]) => post_payjoin(id, body, pool).await,
        _ => Ok(not_found()),
    }
    .unwrap_or_else(|e| e.to_response());

    // Allow CORS for third-party access
    response
        .headers_mut()
        .insert("Access-Control-Allow-Origin", hyper::header::HeaderValue::from_static("*"));

    Ok(response)
}

enum HandlerError {
    PayloadTooLarge,
    InternalServerError,
    BadRequest,
}

impl HandlerError {
    fn to_response(&self) -> Response<Body> {
        let status = match self {
            HandlerError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BadRequest => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let mut res = Response::default();
        *res.status_mut() = status;
        res
    }
}

impl From<hyper::http::Error> for HandlerError {
    fn from(_: hyper::http::Error) -> Self { HandlerError::InternalServerError }
}

async fn post_fallback(id: &str, body: Body, pool: DbPool) -> Result<Response<Body>, HandlerError> {
    let req = hyper::body::to_bytes(body).await.map_err(|_| HandlerError::InternalServerError)?;

    if req.len() > MAX_BUFFER_SIZE {
        return Err(HandlerError::PayloadTooLarge);
    }

    match pool.push_req(id, req.into()).await {
        Ok(_) => (),
        Err(_) => return Err(HandlerError::BadRequest),
    };

    match pool.peek_res(id).await {
        Some(result) => match result {
            Ok(buffered_res) => Ok(Response::new(Body::from(buffered_res))),
            Err(_) => Err(HandlerError::BadRequest),
        },
        None => Ok(Response::builder().status(StatusCode::ACCEPTED).body(Body::empty())?),
    }
}

async fn get_request(id: &str, pool: DbPool) -> Result<Response<Body>, HandlerError> {
    match pool.peek_req(id).await {
        Some(result) => match result {
            Ok(buffered_req) => Ok(Response::new(Body::from(buffered_req))),
            Err(_) => Err(HandlerError::BadRequest),
        },
        None => Ok(Response::builder().status(StatusCode::ACCEPTED).body(Body::empty())?),
    }
}

async fn post_payjoin(id: &str, body: Body, pool: DbPool) -> Result<Response<Body>, HandlerError> {
    let res = hyper::body::to_bytes(body).await.map_err(|_| HandlerError::InternalServerError)?;

    match pool.push_res(id, res.into()).await {
        Ok(_) => Ok(Response::builder().status(StatusCode::NO_CONTENT).body(Body::empty())?),
        Err(_) => Err(HandlerError::BadRequest),
    }
}

fn not_found() -> Response<Body> {
    let mut res = Response::default();
    *res.status_mut() = StatusCode::NOT_FOUND;
    res
}
