use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use hyper::body::Bytes;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, StatusCode};
use tokio::sync::{mpsc, Mutex};
use tracing::info;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

const MAX_BUFFER_SIZE: usize = 65536;
const TIMEOUT_SECS: u64 = 30;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();
    let (req_buffer, res_buffer) = (Buffer::new(), Buffer::new());
    let make_svc = make_service_fn(|_| {
        let req_buffer = req_buffer.clone();
        let res_buffer = res_buffer.clone();
        async move {
            let handler = move |req| handle_web_req(req_buffer.clone(), res_buffer.clone(), req);
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

async fn handle_web_req(
    req_buffer: Buffer,
    res_buffer: Buffer,
    req: Request<Body>,
) -> Result<Response<Body>> {
    let path = req.uri().path().to_string();
    let (parts, body) = req.into_parts();

    let path_segments: Vec<&str> = path.split('/').collect();
    dbg!(&path_segments);
    let mut response = match (parts.method, path_segments.as_slice()) {
        (Method::POST, &["", id]) => post_fallback(id, body, req_buffer, res_buffer).await,
        (Method::GET, &["", id, "receive"]) => get_request(id, req_buffer).await,
        (Method::POST, &["", id, "receive"]) => post_payjoin(id, body, res_buffer).await,
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
}

impl HandlerError {
    fn to_response(&self) -> Response<Body> {
        let status = match self {
            HandlerError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
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

async fn post_fallback(
    _id: &str,
    body: Body,
    req_buffer: Buffer,
    res_buffer: Buffer,
) -> Result<Response<Body>, HandlerError> {
    let req = hyper::body::to_bytes(body).await.map_err(|_| HandlerError::InternalServerError)?;

    if req.len() > MAX_BUFFER_SIZE {
        return Err(HandlerError::PayloadTooLarge);
    }

    req_buffer.push(req).await;

    match res_buffer.peek_with_timeout(Duration::from_secs(TIMEOUT_SECS)).await {
        Some(buffered_res) => Ok(Response::new(Body::from(buffered_res))),
        None => Ok(Response::builder().status(StatusCode::ACCEPTED).body(Body::empty())?),
    }
}

async fn get_request(_id: &str, req_buffer: Buffer) -> Result<Response<Body>, HandlerError> {
    let timeout = Duration::from_secs(30);
    match req_buffer.peek_with_timeout(timeout).await {
        Some(buffered_req) => Ok(Response::new(Body::from(buffered_req))),
        None => Ok(Response::builder().status(StatusCode::ACCEPTED).body(Body::empty())?),
    }
}

async fn post_payjoin(
    _id: &str,
    body: Body,
    res_buffer: Buffer,
) -> Result<Response<Body>, HandlerError> {
    let res = hyper::body::to_bytes(body).await.map_err(|_| HandlerError::InternalServerError)?;

    res_buffer.push(res).await;
    Ok(Response::builder().status(StatusCode::NO_CONTENT).body(Body::empty())?)
}

fn not_found() -> Response<Body> {
    let mut res = Response::default();
    *res.status_mut() = StatusCode::NOT_FOUND;
    res
}

pub(crate) struct Buffer {
    buffer: Arc<Mutex<Bytes>>,
    sender: mpsc::Sender<()>,
    receiver: Arc<Mutex<mpsc::Receiver<()>>>,
}

/// Clone here makes a copy of the Arc pointer, not the underlying data
/// All clones point to the same internal data
impl Clone for Buffer {
    fn clone(&self) -> Self {
        Buffer {
            buffer: Arc::clone(&self.buffer),
            sender: self.sender.clone(),
            receiver: Arc::clone(&self.receiver),
        }
    }
}

impl Buffer {
    fn new() -> Self {
        let (sender, receiver) = mpsc::channel(1);
        Buffer {
            buffer: Arc::new(Mutex::new(Bytes::new())),
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
        }
    }

    async fn push(&self, request: Bytes) {
        info!("push");
        let mut buffer: tokio::sync::MutexGuard<'_, Bytes> = self.buffer.lock().await;
        *buffer = request;
        info!("pushed");
        let _ = self.sender.send(()).await; // signal that a new request has been added
    }

    async fn peek(&self) -> Bytes {
        info!("peek");
        let mut buffer = self.buffer.lock().await;
        let mut contents = buffer.clone();
        if contents.is_empty() {
            drop(buffer);
            // wait for a signal that a new request has been added
            info!("empty, awaiting push");
            self.receiver.lock().await.recv().await;
            info!("pushed, awaiting lock");
            buffer = self.buffer.lock().await;
            contents = buffer.clone();
        }
        info!("peeked");
        contents
    }

    async fn peek_with_timeout(&self, timeout: Duration) -> Option<Bytes> {
        let result = tokio::time::timeout(timeout, self.peek()).await;
        match result {
            Ok(data) => Some(data),
            Err(_) => None,
        }
    }
}
