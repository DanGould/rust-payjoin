use std::error::Error;
use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use payjoin::v2::{MAX_BUFFER_SIZE, RECEIVER};
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, info_span, Instrument};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;
use wtransport::endpoint::IncomingSession;
use wtransport::tls::Certificate;
use wtransport::{Endpoint, RecvStream, SendStream, ServerConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init_logging();

    let cert = Certificate::load("example_cert/cert.pem", "example_cert/key.pem")?;
    let config = ServerConfig::builder()
        .with_bind_address(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433))
        .with_certificate(cert)
        .max_idle_timeout(None)
        .expect("infinite timeout")
        .build();
    let server = Endpoint::server(config)?;

    println!("Serverless payjoin relay awaiting WebTransport connection on port 4433");

    let buffers = (Buffer::new(), Buffer::new());
    for id in 0.. {
        let incoming_session = server.accept().await;
        tokio::spawn(
            handle_connection(incoming_session, buffers.clone())
                .instrument(info_span!("Connection {}", id)),
        );
    }

    Ok(())
}

async fn handle_connection(incoming_session: IncomingSession, buffers: (Buffer, Buffer)) {
    let result = handle_connection_impl(incoming_session, buffers).await;
    error!("{:?}", result);
}

async fn handle_connection_impl(
    incoming_session: IncomingSession,
    (req_buffer, res_buffer): (Buffer, Buffer),
) -> Result<()> {
    info!("Waiting for session request...");

    let session_request = incoming_session.await?;

    info!(
        "New session: Authority: '{}', Path: '{}'",
        session_request.authority(),
        session_request.path()
    );

    let connection = session_request.accept().await?;

    info!("Waiting for data from client...");

    loop {
        tokio::select! {
            stream = connection.accept_bi() => {
                let (mut write, mut read) = stream?;
                info!("Accepted BI stream");

                match read_stream_to_string(&mut read).await? {
                    Some(data) => {
                        if data == RECEIVER {
                            handle_receiver_request(&mut write, &mut read, &req_buffer, &res_buffer).await?;
                        } else {
                            handle_sender_request(&mut write, &data, &req_buffer, &res_buffer).await?;
                        }
                    }
                    None => continue,
                }

                info!("Closing stream");
                write.finish().await?;
            }
        }
    }
}

fn init_logging() {
    let env_filter =
        EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy();

    tracing_subscriber::fmt().with_target(true).with_level(true).with_env_filter(env_filter).init();

    println!("Logging initialized");
}

async fn read_stream_to_string(read: &mut RecvStream) -> Result<Option<String>> {
    let mut buffer = vec![0; MAX_BUFFER_SIZE];
    match read.read(&mut buffer).await? {
        Some(bytes_read) => Ok(Some(std::str::from_utf8(&buffer[..bytes_read])?.to_string())),
        None => Ok(None),
    }
}

async fn handle_receiver_request(
    write: &mut SendStream,
    read: &mut RecvStream,
    req_buffer: &Buffer,
    res_buffer: &Buffer,
) -> Result<()> {
    let buffered_req = req_buffer.peek().await;
    write.write_all(&buffered_req).await?;

    if let Some(response) = read_stream_to_string(read).await? {
        res_buffer.push(response.as_bytes().to_vec()).await;
    }

    Ok(())
}

async fn handle_sender_request(
    write: &mut SendStream,
    data: &str,
    req_buffer: &Buffer,
    res_buffer: &Buffer,
) -> Result<()> {
    req_buffer.push(data.as_bytes().to_vec()).await;
    let response = res_buffer.peek().await;
    write.write_all(&response).await?;
    Ok(())
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
}
