use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::body::Bytes;
use axum::extract::Path;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use payjoin::v2::MAX_BUFFER_SIZE;
use tokio::sync::{mpsc, Mutex};
use tracing::info;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();
    let (req_buffer, res_buffer) = (Buffer::new(), Buffer::new());
    let app = Router::new()
        .route(
            "/:id",
            post({
                let req_buffer = req_buffer.clone();
                let res_buffer = res_buffer.clone();
                move |id, body| post_fallback(id, body, req_buffer, res_buffer)
            }),
        )
        .route(
            "/:id/receive",
            get({
                let req_buffer = req_buffer.clone();
                move |id| get_request(id, req_buffer)
            })
            .post({
                let res_buffer = res_buffer.clone();
                move |id, body| post_payjoin(id, body, res_buffer)
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

async fn post_fallback(
    Path(_id): Path<String>,
    body: Bytes,
    req_buffer: Buffer,
    res_buffer: Buffer,
) -> (StatusCode, Vec<u8>) {
    let body = body.to_vec();
    let body_len = body.len();
    if body_len > MAX_BUFFER_SIZE {
        return (StatusCode::PAYLOAD_TOO_LARGE, b"Payload too large".to_vec());
    }
    req_buffer.push(body).await;

    let timeout = Duration::from_secs(30);
    match res_buffer.peek_with_timeout(timeout).await {
        Some(buffered_res) => (StatusCode::OK, buffered_res),
        None => (StatusCode::ACCEPTED, vec![]),
    }
}

async fn get_request(Path(_id): Path<String>, req_buffer: Buffer) -> (StatusCode, Vec<u8>) {
    let timeout = Duration::from_secs(30);
    match req_buffer.peek_with_timeout(timeout).await {
        Some(buffered_req) => (StatusCode::OK, buffered_req),
        None => (StatusCode::ACCEPTED, vec![]),
    }
}

async fn post_payjoin(
    Path(_id): Path<String>,
    res: Bytes,
    res_buffer: Buffer,
) -> (StatusCode, String) {
    res_buffer.push(res.to_vec()).await;
    (StatusCode::OK, "Received".to_string())
}

pub(crate) struct Buffer {
    buffer: Arc<Mutex<Vec<u8>>>,
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
            buffer: Arc::new(Mutex::new(Vec::new())),
            sender,
            receiver: Arc::new(Mutex::new(receiver)),
        }
    }

    async fn push(&self, request: Vec<u8>) {
        info!("push");
        let mut buffer: tokio::sync::MutexGuard<'_, Vec<u8>> = self.buffer.lock().await;
        *buffer = request;
        info!("pushed");
        let _ = self.sender.send(()).await; // signal that a new request has been added
    }

    async fn peek(&self) -> Vec<u8> {
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

    async fn peek_with_timeout(&self, timeout: Duration) -> Option<Vec<u8>> {
        let result = tokio::time::timeout(timeout, self.peek()).await;
        match result {
            Ok(data) => Some(data),
            Err(_) => None,
        }
    }
}
