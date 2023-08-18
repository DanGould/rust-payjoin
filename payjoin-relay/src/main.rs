use std::net::{Ipv6Addr, SocketAddr};

use wtransport::tls::Certificate;
use wtransport::{Endpoint, ServerConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cert = Certificate::load("example_cert/cert.pem", "example_cert/key.pem")?;
    let config = ServerConfig::builder()
        .with_bind_address(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 4433))
        .with_certificate(cert)
        .build();
    let server = Endpoint::server(config)?;

    println!("Serverless payjoin relay awaiting WebTransport connection on port 4433");
    let incoming_request = server.accept().await.await?;
    let _connection = incoming_request.accept().await?;
    Ok(())
}
