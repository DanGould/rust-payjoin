use axum::routing::get;
use axum::Router;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new().route("/", get(|| async { "Hello, World!" }));

    axum::Server::bind(&"0.0.0.0:8080".parse()?).serve(app.into_make_service()).await?;
    println!("Serverless payjoin relay awaiting HTTP connection on port 8080");
    Ok(())
}
