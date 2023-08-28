use std::error::Error;
use std::net::{Ipv6Addr, SocketAddr};

use anyhow::Result;
use payjoin::v2::{MAX_BUFFER_SIZE, RECEIVE};
use tracing::{debug, error, info, info_span, Instrument};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;
use wtransport::endpoint::IncomingSession;
use wtransport::tls::Certificate;
use wtransport::{Endpoint, RecvStream, SendStream, ServerConfig};

mod db;
use crate::db::DbPool;

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
    let pool = DbPool::new().await?;
    for id in 0.. {
        let incoming_session = server.accept().await;
        tokio::spawn(
            handle_connection(incoming_session, pool.clone())
                .instrument(info_span!("Connection {}", id)),
        );
    }

    Ok(())
}

async fn handle_connection(incoming_session: IncomingSession, pool: DbPool) {
    let result = handle_connection_impl(incoming_session, pool).await;
    error!("{:?}", result);
}

async fn handle_connection_impl(incoming_session: IncomingSession, pool: DbPool) -> Result<()> {
    info!("Waiting for session request...");

    let session_request = incoming_session.await?;
    let subdirectory: String;

    if let Some(pos) = session_request.path().rfind('/') {
        subdirectory = session_request.path()[pos + 1..].to_string();
    } else {
        subdirectory = session_request.path().to_string();
    }

    let pubkey_id: String;

    if let Some(pos) = subdirectory.find('?') {
        pubkey_id = subdirectory[..pos].to_string();
    } else {
        pubkey_id = subdirectory;
    }

    println!("Subdirectory: {}", pubkey_id);

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
                info!("Accepted BI stream for pubkey_id {}", pubkey_id);

                match read_stream_to_string(&mut read).await? {
                    Some(data) => {
                        let mut parts = data.split_whitespace();
                        let operation = parts.next().ok_or(anyhow::anyhow!("No operation"))?;
                        if operation == RECEIVE {
                            let pubkey_id = parts.next().ok_or(anyhow::anyhow!("No pubkey_id"))?;
                            info!("Received receiver enroll request for pubkey_id {}", pubkey_id);
                            handle_receiver_request(&mut write, &mut read, &pool, pubkey_id).await?;
                        } else {
                            handle_sender_request(&mut write, &data, &pool, &pubkey_id).await?;
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
    pool: &DbPool,
    pubkey_id: &str,
) -> Result<()> {
    let buffered_req = pool.peek_req(pubkey_id).await?;
    write.write_all(&buffered_req).await?;

    if let Some(response) = read_stream_to_string(read).await? {
        pool.push_res(pubkey_id, response.as_bytes().to_vec()).await?;
    }

    Ok(())
}

async fn handle_sender_request(
    write: &mut SendStream,
    data: &str,
    pool: &DbPool,
    pubkey_id: &str,
) -> Result<()> {
    pool.push_req(pubkey_id, data.as_bytes().to_vec()).await?;
    debug!("pushed req");
    let response = pool.peek_res(pubkey_id).await?;
    debug!("peek req");
    write.write_all(&response).await?;
    Ok(())
}
