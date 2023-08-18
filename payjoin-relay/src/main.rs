use std::net::{Ipv6Addr, SocketAddr};
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = TcpListener::bind(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 8080)).await?;

    println!("Serverless payjoin relay awaiting WebTransport connection on port 4433");
    let (_stream, _) = server.accept().await?;
    Ok(())
}
