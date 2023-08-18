use std::convert::Infallible;
use std::net::SocketAddr;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(|_req| async {
            Ok::<_, Infallible>(Response::new(Body::from("Hello, World!")))
        }))
    });
    println!("Serverless payjoin relay awaiting HTTP connection on port 8080");
    hyper::Server::bind(&"0.0.0.0:8080".parse()?).serve(make_svc).await?;
    Ok(())
}
