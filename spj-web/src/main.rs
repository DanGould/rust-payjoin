//! Web wallets for the silent payjoin demo: Bob's silent payment wallet,
//! and three payers (Carol's payjoin wallet, Alice's silent payment wallet,
//! and an exchange) on a regtest node with a payjoin directory and OHTTP
//! relay on localhost.
//!
//! ```text
//! spj-web [--port N] [--explorer URL] [--pace-ms N] [--node-info PATH]
//! ```
//!
//! Each wallet runs as its own task and reaches the others only through the
//! directory. The page sends what a user would tap, and gets every step back
//! as an event. `--node-info` writes the node's RPC port and cookie file as
//! JSON once the wallets are funded, for a mempool explorer to follow the
//! chain. Everything binds to 127.0.0.1 and stops when the process does.

mod bob;
mod events;
mod payers;
mod shape;

use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Path as UrlPath, State};
use axum::http::{header, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bitcoin::Amount;
use futures::stream::{self, Stream, StreamExt};
use serde_json::{json, Value};
use spj_demo::flow::Regtest;
use spj_demo::net::Error;
use spj_demo::video::Node;
use spj_demo::wallet::{KeyKind, Keychain};
use tokio::sync::{mpsc, oneshot};

use crate::events::Hub;

/// What every wallet task shares: the chain, the mailroom, and the page.
pub struct Shared {
    pub regtest: Regtest,
    pub hub: Hub,
    /// Where the payers' "view in explorer" links point.
    pub explorer: String,
}

struct Options {
    port: u16,
    explorer: String,
    pace: Duration,
    node_info: Option<PathBuf>,
}

fn options() -> Result<Options, Error> {
    let mut options = Options {
        port: 3000,
        explorer: "http://127.0.0.1:4200".into(),
        pace: Duration::from_millis(1100),
        node_info: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--port" => options.port = value()?.parse()?,
            "--explorer" => options.explorer = value()?.trim_end_matches('/').to_string(),
            "--pace-ms" => options.pace = Duration::from_millis(value()?.parse()?),
            "--node-info" => options.node_info = Some(value()?.into()),
            _ => return Err(format!("unknown argument {flag}").into()),
        }
    }
    Ok(options)
}

#[derive(Clone)]
struct App {
    shared: Arc<Shared>,
    bob: mpsc::Sender<bob::Command>,
    carol: mpsc::Sender<payers::Command>,
    alice: mpsc::Sender<payers::Command>,
    exchange: mpsc::Sender<payers::Command>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Error> {
    let options = options()?;
    let regtest = Regtest::start().await?;

    let (mut one_time_coins, mut contact_coins) = bob::Bob::keychains();
    let mut alice = Keychain::new("alice", "alice", KeyKind::P2tr, 0);
    let mut exchange = Keychain::new("exchange", "exchange", KeyKind::P2tr, 0);
    let coins = |n, sat| vec![Amount::from_sat(sat); n];
    regtest.fund(&mut one_time_coins, &coins(4, 30_000))?;
    regtest.fund(&mut contact_coins, &coins(6, 30_000))?;
    regtest.fund(&mut alice, &coins(3, 200_000))?;
    regtest.fund(&mut exchange, &coins(6, 300_000))?;
    let carol = regtest.node.create_wallet("carol")?;
    regtest.client().send_to_address(&carol.new_address()?, Amount::from_sat(500_000))?;
    regtest.mine(1)?;

    if let Some(path) = &options.node_info {
        let node = Node::from(&regtest.node);
        let info = json!({ "rpc_port": node.rpc_port, "cookie": node.cookie });
        std::fs::write(path, info.to_string())?;
    }

    let shared = Arc::new(Shared {
        regtest,
        hub: Hub::new(options.pace),
        explorer: options.explorer.clone(),
    });
    let spawn_payer = |name, coins| {
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(payers::Payer::new(shared.clone(), name, coins).run(rx));
        tx
    };
    let app = App {
        carol: spawn_payer("carol", payers::Coins::Core(carol)),
        alice: spawn_payer("alice", payers::Coins::Keys(alice)),
        exchange: spawn_payer("exchange", payers::Coins::Keys(exchange)),
        bob: {
            let (tx, rx) = mpsc::channel(8);
            tokio::spawn(bob::Bob::new(shared.clone(), one_time_coins, contact_coins).run(rx));
            tx
        },
        shared: shared.clone(),
    };

    let router = Router::new()
        .route("/api/events", get(events))
        .route("/api/state", get(state))
        .route("/api/stage", post(stage))
        .route("/api/pace", post(pace))
        .route("/api/release", post(release))
        .route("/api/bob/one-time", post(bob_one_time))
        .route("/api/bob/contact", post(bob_contact))
        .route("/api/bob/awake", post(bob_awake))
        .route("/api/{payer}/pay", post(pay))
        .route("/api/exchange/contact", post(exchange_contact))
        .route("/api/exchange/pay-contact", post(exchange_pay_contact))
        .route("/", get(|| file("index.html".into())))
        .route("/{*path}", get(|UrlPath(path): UrlPath<String>| file(path)))
        .with_state(app);

    let listener = tokio::net::TcpListener::bind(("127.0.0.1", options.port)).await?;
    println!("wallets http://127.0.0.1:{}", options.port);
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    // Not a graceful shutdown: an open page's event stream never ends on its
    // own. Returning drops the node and the mailroom, which stops them.
    tokio::select! {
        served = axum::serve(listener, router) => served?,
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    Ok(())
}

async fn events(State(app): State<App>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let (history, rx) = app.shared.hub.subscribe();
    let past = stream::iter(history);
    let live = stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(event) => return Some((event, rx)),
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => return None,
            }
        }
    });
    let all = past.chain(live).map(|event| Ok(Event::default().data(event.to_string())));
    Sse::new(all).keep_alive(KeepAlive::default())
}

async fn state(State(app): State<App>) -> Json<Value> {
    let height = spj_demo::chain::height(app.shared.regtest.client()).unwrap_or_default();
    Json(json!({ "explorer": app.shared.explorer, "height": height }))
}

/// Which payer's phone is on stage. Only the page cares.
async fn stage(State(app): State<App>, Json(body): Json<Value>) -> Json<Value> {
    app.shared.hub.emit("stage", body.clone());
    Json(body)
}

/// Set the pause between steps (`ms`) and whether steps wait for a release
/// (`held`).
async fn pace(State(app): State<App>, Json(body): Json<Value>) -> Json<Value> {
    let pace = body["ms"].as_u64().map(Duration::from_millis);
    app.shared.hub.set_pace(pace, body["held"].as_bool());
    Json(body)
}

/// Let the wallets go on: past the steps taken so far, or with `until` and
/// `n` until the `n`th event of that kind.
async fn release(State(app): State<App>, Json(body): Json<Value>) -> Json<Value> {
    match body["until"].as_str() {
        Some(kind) =>
            app.shared.hub.release_until(kind.to_string(), body["n"].as_u64().unwrap_or(1)),
        None => app.shared.hub.release(),
    }
    Json(body)
}

type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;

fn failed(e: impl ToString) -> (StatusCode, Json<Value>) {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": e.to_string() })))
}

/// Send a command to a wallet task and wait for its answer.
async fn ask<C>(to: &mpsc::Sender<C>, make: impl FnOnce(bob::Reply) -> C) -> ApiResult {
    let (reply, answer) = oneshot::channel();
    to.send(make(reply)).await.map_err(failed)?;
    answer.await.map_err(failed)?.map(Json).map_err(failed)
}

fn amount(body: &Value) -> Result<Amount, (StatusCode, Json<Value>)> {
    body["amount"].as_u64().map(Amount::from_sat).ok_or_else(|| failed("amount in sats"))
}

async fn bob_one_time(State(app): State<App>, Json(body): Json<Value>) -> ApiResult {
    let amount = amount(&body)?;
    ask(&app.bob, |reply| bob::Command::OneTime { amount, reply }).await
}

async fn bob_contact(State(app): State<App>) -> ApiResult {
    ask(&app.bob, |reply| bob::Command::Contact { reply }).await
}

async fn bob_awake(State(app): State<App>, Json(body): Json<Value>) -> ApiResult {
    let awake = body["awake"].as_bool().unwrap_or(true);
    ask(&app.bob, |reply| bob::Command::Awake { awake, reply }).await
}

async fn pay(
    State(app): State<App>,
    UrlPath(payer): UrlPath<String>,
    Json(body): Json<Value>,
) -> ApiResult {
    let to = match payer.as_str() {
        "carol" => &app.carol,
        "alice" => &app.alice,
        _ => return Err(failed(format!("no payer {payer}"))),
    };
    let uri = body["uri"].as_str().ok_or_else(|| failed("uri"))?.to_string();
    ask(to, |reply| payers::Command::Pay { uri, reply }).await
}

async fn exchange_contact(State(app): State<App>, Json(body): Json<Value>) -> ApiResult {
    let uri = body["uri"].as_str().ok_or_else(|| failed("uri"))?.to_string();
    ask(&app.exchange, |reply| payers::Command::AddContact { uri, reply }).await
}

async fn exchange_pay_contact(State(app): State<App>, Json(body): Json<Value>) -> ApiResult {
    let amount = amount(&body)?;
    let reply_by = Duration::from_secs(body["reply_by"].as_u64().unwrap_or(60));
    ask(&app.exchange, |reply| payers::Command::PayContact { amount, reply_by, reply }).await
}

/// A file from `static/`, never from outside it.
async fn file(path: String) -> Response {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("static");
    if path.split('/').any(|part| part == ".." || part.is_empty()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let kind = match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript",
        Some("css") => "text/css",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("woff2") => "font/woff2",
        _ => "application/octet-stream",
    };
    match tokio::fs::read(root.join(&path)).await {
        Ok(bytes) => ([(header::CONTENT_TYPE, kind), (header::CACHE_CONTROL, "no-store")], bytes)
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
