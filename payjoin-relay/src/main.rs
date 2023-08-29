use std::net::{Ipv6Addr, SocketAddr};

use anyhow::Result;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use payjoin::v2::RECEIVE;
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::handshake::server::Request;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_hdr_async, WebSocketStream};
use tracing::{debug, error, info, info_span, Instrument};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

type Stream = SplitStream<WebSocketStream<TcpStream>>;
type Sink = SplitSink<WebSocketStream<TcpStream>, Message>;

mod db;
use crate::db::DbPool;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();

    let server = TcpListener::bind(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 8080)).await?;

    let pool = DbPool::new().await?;
    println!("Serverless payjoin relay awaiting WebSockets connection on port 8080");
    for id in 0.. {
        let (connection, _) = server.accept().await?;
        tokio::spawn(
            handle_connection(connection, pool.clone()).instrument(info_span!("Connection {}", id)),
        );
    }

    Ok(())
}

async fn handle_connection(connection: TcpStream, pool: DbPool) {
    let result = handle_connection_impl(connection, pool).await;
    error!("{:?}", result);
}

async fn handle_connection_impl(connection: TcpStream, pool: DbPool) -> Result<()> {
    info!("Waiting to establish a stream");
    //let stream = accept_async(connection).await?;
    let mut pubkey_id = String::new();
    let stream = accept_hdr_async(connection, |req: &Request, res| {
        pubkey_id = if let Some(pos) = req.uri().path().rfind('/') {
            &req.uri().path()[pos + 1..]
        } else {
            req.uri().path()
        }
        .to_string();
        if let Some(pos) = pubkey_id.find('?') {
            pubkey_id = pubkey_id[..pos].to_string()
        };
        // concat pubkey_id to 16 chars to fit postgres table name
        pubkey_id = shorten_string(&pubkey_id);
        debug!("Subdirectory: {}", pubkey_id);
        Ok(res)
    })
    .await?;
    let (mut write, mut read) = stream.split();
    info!("Accepted stream");
    match read_stream_to_string(&mut read).await? {
        Some(data) => {
            let mut parts = data.split_whitespace();
            let operation = parts.next().ok_or(anyhow::anyhow!("No operation"))?;
            if operation == RECEIVE {
                let pubkey_id = parts.next().ok_or(anyhow::anyhow!("No pubkey_id"))?;
                let pubkey_id = shorten_string(pubkey_id);
                info!("Received receiver enroll request for pubkey_id {}", pubkey_id);
                handle_receiver_request(&mut write, &mut read, &pool, &pubkey_id).await?;
            } else {
                handle_sender_request(&mut write, &data, &pool, &pubkey_id).await?;
            }
        }
        None => (),
    }
    info!("Closing stream");
    write.close().await?;
    Ok(())
}

fn init_logging() {
    let env_filter =
        EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy();

    tracing_subscriber::fmt().with_target(true).with_level(true).with_env_filter(env_filter).init();

    println!("Logging initialized");
}

async fn read_stream_to_string(read: &mut Stream) -> Result<Option<String>> {
    match read.next().await {
        Some(msg) => Ok(Some(msg?.to_string())),
        None => Ok(None),
    }
}

async fn handle_receiver_request(
    write: &mut Sink,
    read: &mut Stream,
    pool: &DbPool,
    pubkey_id: &str,
) -> Result<()> {
    let buffered_req = pool.peek_req(pubkey_id).await?;
    write.send(Message::binary(buffered_req)).await?;

    if let Some(response) = read_stream_to_string(read).await? {
        pool.push_res(pubkey_id, response.as_bytes().to_vec()).await?;
    }

    Ok(())
}

async fn handle_sender_request(
    write: &mut Sink,
    data: &str,
    pool: &DbPool,
    pubkey_id: &str,
) -> Result<()> {
    pool.push_req(pubkey_id, data.as_bytes().to_vec()).await?;
    debug!("pushed req");
    let response = pool.peek_res(pubkey_id).await?;
    debug!("peek req");
    write.send(response.into()).await?;
    Ok(())
}

fn shorten_string(input: &str) -> String { input.chars().take(8).collect() }
