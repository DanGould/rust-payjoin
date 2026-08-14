use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use axum::body::{Body, Bytes};
use axum::http::header::{HeaderValue, ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE};
use axum::http::{Method, Request, Response, StatusCode, Uri};
use http_body_util::BodyExt;
use payjoin::directory::{ShortId, ShortIdError, ENCAPSULATED_MESSAGE_BYTES};
use tracing::{error, warn};

use crate::admission::{
    Admission, PowThenZk, Rejection, POW_NONCE_BYTES, PROOF_BYTES, TOKEN_BYTES,
};
use crate::db::board::{BoardStore, Error as BoardError, BLOB_BYTES};
use crate::db::queues::{Error as QueueError, QueueStore, FRAME_BYTES};
use crate::db::{Db, Error as DbError, SendableError};
use crate::ohttp_relay::SentinelTag;

const CHACHA20_POLY1305_NONCE_LEN: usize = 32; // chacha20poly1305 n_k
const POLY1305_TAG_SIZE: usize = 16;
/// Bytes OHTTP response encapsulation adds to a padded bhttp response.
const ENCAPSULATION_OVERHEAD_BYTES: usize = CHACHA20_POLY1305_NONCE_LEN + POLY1305_TAG_SIZE;
pub const BHTTP_REQ_BYTES: usize = ENCAPSULATED_MESSAGE_BYTES - ENCAPSULATION_OVERHEAD_BYTES;
const V1_MAX_BUFFER_SIZE: usize = 65536;

/// Frames returned by one queue mailbox read.
const K_FRAMES_PER_RESPONSE: usize = 4;

/// The fixed size of every encapsulated queue read response.
///
/// A page of [`K_FRAMES_PER_RESPONSE`] frames cannot fit the standard
/// [`ENCAPSULATED_MESSAGE_BYTES`] response, so queue reads form their
/// own fixed size class. Padding every queue read to the same length
/// keeps the response independent of how many real frames it carries:
/// the transporting relay learns that a queue read happened, but never
/// how full the queue is. All other responses, including queue appends,
/// keep the standard v2 mailbox size.
const ENCAPSULATED_QUEUE_RESPONSE_BYTES: usize = 4 * ENCAPSULATED_MESSAGE_BYTES;

// A queue response page plus bhttp framing and headers must fit within
// the padded response, with slack for the header block.
const _: () = assert!(
    K_FRAMES_PER_RESPONSE * FRAME_BYTES + 256
        <= ENCAPSULATED_QUEUE_RESPONSE_BYTES - ENCAPSULATION_OVERHEAD_BYTES
);

/// Response header carrying the index to resume reading a queue from.
const NEXT_INDEX_HEADER: &str = "x-pj-next";

/// Blobs per bulletin board read response.
const K_BLOBS_PER_RESPONSE: usize = 16;

/// The fixed size of every encapsulated board read response.
///
/// A page of [`K_BLOBS_PER_RESPONSE`] blobs cannot fit the standard
/// response, so board reads form their own fixed size class with the
/// same rationale as queue reads: length reveals only the operation
/// class, never how many live entries the page carries.
const ENCAPSULATED_BOARD_RESPONSE_BYTES: usize = 2 * ENCAPSULATED_MESSAGE_BYTES;

// A board page plus bhttp framing and headers must fit within the
// padded response, with slack for the header block.
const _: () = assert!(
    K_BLOBS_PER_RESPONSE * BLOB_BYTES + 256
        <= ENCAPSULATED_BOARD_RESPONSE_BYTES - ENCAPSULATION_OVERHEAD_BYTES
);

const V1_REJECT_RES_JSON: &str =
    r#"{{"errorCode": "original-psbt-rejected ", "message": "Body is not a string"}}"#;
const V1_UNAVAILABLE_RES_JSON: &str = r#"{{"errorCode": "unavailable", "message": "V2 receiver offline. V1 sends require synchronous communications."}}"#;
const V1_VERSION_UNSUPPORTED_RES_JSON: &str =
    r#"{"errorCode": "version-unsupported", "supported": [2], "message": "V1 is not supported"}"#;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Opaque blocklist of Bitcoin addresses stored as script pubkeys.
///
/// Addresses are converted to `ScriptBuf` at parse time so that
/// screening only requires a `HashSet::contains` on raw scripts,
/// avoiding address-encoding round-trips and bech32 case issues.
#[derive(Clone)]
pub struct BlockedAddresses(
    pub(crate) Arc<tokio::sync::RwLock<std::collections::HashSet<bitcoin::ScriptBuf>>>,
);

impl BlockedAddresses {
    pub fn empty() -> Self {
        Self(Arc::new(tokio::sync::RwLock::new(std::collections::HashSet::new())))
    }

    pub fn from_address_lines(text: &str) -> Self {
        Self(Arc::new(tokio::sync::RwLock::new(parse_address_lines(text))))
    }

    /// Replace the contents with scripts parsed from newline-delimited
    /// address text.  Returns the number of entries after update.
    pub async fn update_from_lines(&self, text: &str) -> usize {
        let scripts = parse_address_lines(text);
        let count = scripts.len();
        *self.0.write().await = scripts;
        count
    }
}

/// V1 protocol configuration.
///
/// Its presence in [`Service`] enables the V1 fallback path;
/// its contents carry optional blocklist screening.
#[derive(Clone, Default)]
pub struct V1 {
    blocked_addresses: Option<BlockedAddresses>,
}

impl V1 {
    pub fn new(blocked_addresses: Option<BlockedAddresses>) -> Self { Self { blocked_addresses } }
}

fn parse_address_lines(text: &str) -> std::collections::HashSet<bitcoin::ScriptBuf> {
    text.lines()
        .filter_map(|l| {
            let trimmed = l.trim();
            if trimmed.is_empty() {
                return None;
            }
            match trimmed.parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>() {
                Ok(addr) => Some(addr.assume_checked().script_pubkey()),
                Err(e) => {
                    tracing::warn!("Skipping unparsable blocked address {trimmed:?}: {e}");
                    None
                }
            }
        })
        .collect()
}

/// Bulletin board configuration: storage plus the admission mechanism
/// gating submissions.
#[derive(Clone)]
pub struct Board {
    store: BoardStore,
    admission: Arc<dyn Admission>,
    /// Bytes of admission material a submission carries ahead of the
    /// blob it stores.
    admission_bytes: usize,
}

impl Board {
    /// A board gated by proof of work: submissions are `nonce || blob`.
    pub fn new(store: BoardStore, admission: Arc<dyn Admission>) -> Self {
        Self { store, admission, admission_bytes: POW_NONCE_BYTES }
    }

    /// A board gated by proof of work and then a zero-knowledge
    /// credential: submissions are `nonce || proof || blob`.
    ///
    /// Taking the ordered pair rather than any [`Admission`] is what
    /// keeps verification behind the cheap gate: an operator cannot
    /// configure the expensive check on its own.
    pub fn with_credential(store: BoardStore, admission: Arc<PowThenZk>) -> Self {
        Self { store, admission, admission_bytes: POW_NONCE_BYTES + PROOF_BYTES }
    }
}

#[derive(Clone)]
pub struct Service<D: Db> {
    db: D,
    ohttp: ohttp::Server,
    sentinel_tag: SentinelTag,
    v1: Option<V1>,
    queues: Option<QueueStore>,
    queue_admission: Option<Arc<dyn Admission>>,
    board: Option<Board>,
}

impl<D: Db, B> tower::Service<Request<B>> for Service<D>
where
    B: axum::body::HttpBody<Data = Bytes> + Send + 'static,
    B::Error: Into<BoxError>,
{
    type Response = Response<Body>;
    type Error = anyhow::Error;
    type Future =
        Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<B>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move { this.serve_request(req).await })
    }
}

impl<D: Db> Service<D> {
    pub fn new(db: D, ohttp: ohttp::Server, sentinel_tag: SentinelTag, v1: Option<V1>) -> Self {
        Self { db, ohttp, sentinel_tag, v1, queues: None, queue_admission: None, board: None }
    }

    /// Serve queue mailbox endpoints (`/q/{id}`) from `queues`. Without
    /// this, queue routes do not exist and requests to them return the
    /// same responses they did before queues were introduced.
    pub fn with_queues(mut self, queues: QueueStore) -> Self {
        self.queues = Some(queues);
        self
    }

    /// Require queue appends to pass `admission`, carrying an
    /// owner-minted token ahead of the frame. Without this, any party
    /// that knows a queue id may append to it, exactly as before
    /// admission existed. Queue reads are never gated.
    pub fn with_queue_admission(mut self, admission: Arc<dyn Admission>) -> Self {
        self.queue_admission = Some(admission);
        self
    }

    /// Serve bulletin board endpoints (`/board`). Without this, board
    /// routes do not exist and requests to them return the same
    /// responses they did before the board was introduced.
    pub fn with_board(mut self, board: Board) -> Self {
        self.board = Some(board);
        self
    }

    async fn serve_request<B>(&self, req: Request<B>) -> Result<Response<Body>>
    where
        B: axum::body::HttpBody<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or_default().to_string();
        let (parts, body) = req.into_parts();
        let path_segments: Vec<&str> = path.split('/').collect();

        // Best-effort validation that the relay and gateway aren't on the same
        // payjoin-mailroom instance
        if let Some(header_value) = parts
            .headers
            .get(crate::ohttp_relay::sentinel::HEADER_NAME)
            .and_then(|v| v.to_str().ok())
        {
            if crate::ohttp_relay::sentinel::is_self_loop(&self.sentinel_tag, header_value) {
                warn!("Rejected OHTTP request from same-instance relay");
                return Ok(HandlerError::Forbidden(anyhow::anyhow!(
                    "Relay and gateway must be operated by different entities"
                ))
                .to_response());
            }
        }

        let mut response = match (parts.method, path_segments.as_slice()) {
            (Method::POST, ["", ".well-known", "ohttp-gateway"]) =>
                self.handle_ohttp_gateway(body).await,
            (Method::GET, ["", ".well-known", "ohttp-gateway"]) =>
                self.handle_ohttp_gateway_get(&query).await,
            (Method::POST, ["", ""]) => self.handle_ohttp_gateway(body).await,
            (Method::GET, ["", "ohttp-keys"]) => self.get_ohttp_keys().await,
            (Method::POST, ["", id]) => self.handle_post_v1(id, query, body).await,
            (Method::GET, ["", "health"]) => self.health_check().await,
            (Method::GET, ["", ""]) => handle_directory_home_path().await,
            _ => Ok(not_found()),
        }
        .unwrap_or_else(|e| e.to_response());

        // Allow CORS for third-party access
        response.headers_mut().insert(ACCESS_CONTROL_ALLOW_ORIGIN, HeaderValue::from_static("*"));
        Ok(response)
    }

    /// Route POST /{id}: forward to V1 fallback when enabled, otherwise reject.
    async fn handle_post_v1<B>(
        &self,
        id: &str,
        query: String,
        body: B,
    ) -> Result<Response<Body>, HandlerError>
    where
        B: axum::body::HttpBody<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        if self.v1.is_some() {
            self.post_fallback_v1(id, query, body).await
        } else {
            Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header(CONTENT_TYPE, "application/json")
                .body(full(V1_VERSION_UNSUPPORTED_RES_JSON))?)
        }
    }

    /// Handle an encapsulated OHTTP request and return an encapsulated response
    async fn handle_ohttp_gateway<B>(&self, body: B) -> Result<Response<Body>, HandlerError>
    where
        B: axum::body::HttpBody<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let ohttp_body = body
            .collect()
            .await
            .map_err(|e| HandlerError::BadRequest(anyhow::anyhow!(e.into())))?
            .to_bytes();

        // Decapsulate OHTTP request
        let (bhttp_req, res_ctx) = self
            .ohttp
            .decapsulate(&ohttp_body)
            .map_err(|e| HandlerError::OhttpKeyRejection(e.into()))?;
        let mut cursor = std::io::Cursor::new(bhttp_req);
        let req = bhttp::Message::read_bhttp(&mut cursor)
            .map_err(|e| HandlerError::BadRequest(e.into()))?;
        let uri = Uri::builder()
            .scheme(req.control().scheme().unwrap_or_default())
            .authority(req.control().authority().unwrap_or_default())
            .path_and_query(req.control().path().unwrap_or_default())
            .build()?;
        let body = req.content().to_vec();
        let mut http_req =
            Request::builder().uri(uri).method(req.control().method().unwrap_or_default());
        for header in req.header().fields() {
            http_req = http_req.header(header.name(), header.value())
        }
        let request = http_req.body(full(body))?;

        // The response size class is a function of the requested route,
        // fixed before the request is handled so it cannot depend on the
        // outcome.
        let encapsulated_response_bytes = self.encapsulated_response_bytes(&request);

        // Handle decapsulated request
        let response = self.handle_decapsulated_request(request).await?;

        // Encapsulate OHTTP response
        let (parts, body) = response.into_parts();
        let mut bhttp_res = bhttp::Message::response(
            bhttp::StatusCode::try_from(parts.status.as_u16())
                .map_err(|e| HandlerError::InternalServerError(e.into()))?,
        );
        for (name, value) in parts.headers.iter() {
            bhttp_res.put_header(name.as_str(), value.to_str().unwrap_or_default());
        }
        let full_body = body
            .collect()
            .await
            .map_err(|e| HandlerError::InternalServerError(e.into()))?
            .to_bytes();
        bhttp_res.write_content(&full_body);
        let mut bhttp_bytes = Vec::new();
        bhttp_res
            .write_bhttp(bhttp::Mode::KnownLength, &mut bhttp_bytes)
            .map_err(|e| HandlerError::InternalServerError(e.into()))?;
        bhttp_bytes.resize(encapsulated_response_bytes - ENCAPSULATION_OVERHEAD_BYTES, 0);
        let ohttp_res = res_ctx
            .encapsulate(&bhttp_bytes)
            .map_err(|e| HandlerError::InternalServerError(e.into()))?;
        assert!(ohttp_res.len() == encapsulated_response_bytes, "Unexpected OHTTP response size");
        Ok(Response::new(full(ohttp_res)))
    }

    /// The fixed size to pad the encapsulated response of a decapsulated
    /// request to.
    ///
    /// Only queue reads use a larger class than the standard
    /// [`ENCAPSULATED_MESSAGE_BYTES`], because their page of frames does
    /// not fit it. When queues are not enabled the standard size applies
    /// everywhere, exactly as before queues existed.
    fn encapsulated_response_bytes<B>(&self, req: &Request<B>) -> usize {
        let path = req.uri().path();
        let path_segments: Vec<&str> = path.split('/').collect();
        match (req.method(), path_segments.as_slice()) {
            (&Method::GET, &["", "q", _]) if self.queues.is_some() =>
                ENCAPSULATED_QUEUE_RESPONSE_BYTES,
            (&Method::GET, &["", "board"]) if self.board.is_some() =>
                ENCAPSULATED_BOARD_RESPONSE_BYTES,
            _ => ENCAPSULATED_MESSAGE_BYTES,
        }
    }

    async fn handle_decapsulated_request(
        &self,
        req: Request<Body>,
    ) -> Result<Response<Body>, HandlerError> {
        let path = req.uri().path().to_string();
        let query = req.uri().query().unwrap_or_default().to_string();
        let (parts, body) = req.into_parts();
        let path_segments: Vec<&str> = path.split('/').collect();
        match (parts.method, path_segments.as_slice()) {
            (Method::POST, &["", "q", id]) => match &self.queues {
                Some(queues) => self.post_queue(queues, id, body).await,
                None => Ok(not_found()),
            },
            (Method::GET, &["", "q", id]) => match &self.queues {
                Some(queues) => self.get_queue(queues, id, &query).await,
                None => Ok(not_found()),
            },
            // Without a board, "board" falls through to the mailbox
            // arms below, which reject it as an invalid id exactly as
            // they did before the board existed.
            (Method::POST, &["", "board"]) if self.board.is_some() => self.post_board(body).await,
            (Method::GET, &["", "board"]) if self.board.is_some() => self.get_board(&query).await,
            (Method::POST, &["", id]) => self.post_mailbox(id, body).await,
            (Method::GET, &["", id]) => self.get_mailbox(id).await,
            (Method::PUT, &["", id]) if self.v1.is_some() => self.put_payjoin_v1(id, body).await,
            _ => Ok(not_found()),
        }
    }

    async fn post_mailbox(&self, id: &str, body: Body) -> Result<Response<Body>, HandlerError> {
        let none_response = Response::builder().status(StatusCode::OK).body(empty())?;
        let id = ShortId::from_str(id)?;
        let req = body
            .collect()
            .await
            .map_err(|e| HandlerError::InternalServerError(e.into()))?
            .to_bytes();
        if req.len() > V1_MAX_BUFFER_SIZE {
            return Err(HandlerError::PayloadTooLarge);
        }
        match self.db.post_v2_payload(&id, req.into()).await {
            Ok(_) => Ok(none_response),
            Err(e) => Err(HandlerError::InternalServerError(e.into())),
        }
    }

    async fn get_mailbox(&self, id: &str) -> Result<Response<Body>, HandlerError> {
        let id = ShortId::from_str(id)?;
        let timeout_response = Response::builder().status(StatusCode::ACCEPTED).body(empty())?;
        handle_peek(self.db.wait_for_v2_payload(&id).await, timeout_response)
    }

    /// Route POST /q/{id}: append one frame to a queue mailbox.
    ///
    /// Queue endpoints report client errors as inner statuses so they
    /// stay encapsulated: a rejected request produces the same
    /// fixed-size response as an accepted one on the wire. Only
    /// internal failures escape as unencapsulated errors.
    ///
    /// With queue admission configured, the body is `token || frame`
    /// and only a token minted by the mailbox owner admits the append;
    /// a spent token is refused as a conflict rather than acknowledged
    /// like a board replay, because the token does not commit to the
    /// frame, so an acknowledgment could claim an arbitrary frame was
    /// stored. Without admission the body is the frame alone, exactly
    /// as before admission existed.
    async fn post_queue(
        &self,
        queues: &QueueStore,
        id: &str,
        body: Body,
    ) -> Result<Response<Body>, HandlerError> {
        let Ok(id) = ShortId::from_str(id) else {
            return inner_status(StatusCode::BAD_REQUEST);
        };
        let body = body
            .collect()
            .await
            .map_err(|e| HandlerError::InternalServerError(e.into()))?
            .to_bytes();
        let (frame, admitted_tag) = match &self.queue_admission {
            Some(admission) => {
                let (token, frame) = body.split_at(body.len().min(TOKEN_BYTES));
                let mut input = Vec::with_capacity(id.as_slice().len() + token.len());
                input.extend_from_slice(id.as_slice());
                input.extend_from_slice(token);
                let tag = match admission.verify(&input).await {
                    Ok(tag) => tag,
                    Err(Rejection::Malformed) => return inner_status(StatusCode::BAD_REQUEST),
                    Err(Rejection::InsufficientWork) =>
                        return inner_status(StatusCode::TOO_MANY_REQUESTS),
                    Err(Rejection::Unauthorized) => return inner_status(StatusCode::UNAUTHORIZED),
                    Err(Rejection::Conflict) => return inner_status(StatusCode::CONFLICT),
                    Err(Rejection::Unavailable) =>
                        return inner_status(StatusCode::SERVICE_UNAVAILABLE),
                };
                match admission.seen(&tag).await {
                    Ok(false) => {}
                    Ok(true) => return inner_status(StatusCode::CONFLICT),
                    Err(e) => return Err(HandlerError::InternalServerError(e.into())),
                }
                (frame, Some((admission, tag)))
            }
            None => (&body[..], None),
        };
        match queues.append(&id, frame).await {
            Ok(()) => {}
            Err(QueueError::InvalidFrameSize(len)) => {
                warn!("Queue frame must be exactly {FRAME_BYTES} bytes, got {len}");
                return inner_status(StatusCode::BAD_REQUEST);
            }
            Err(QueueError::QueueFull) => return inner_status(StatusCode::TOO_MANY_REQUESTS),
            Err(QueueError::OverCapacity) => return inner_status(StatusCode::SERVICE_UNAVAILABLE),
            Err(QueueError::IO(e)) => return Err(HandlerError::InternalServerError(e.into())),
        }
        if let Some((admission, tag)) = admitted_tag {
            // Record the tag only now that the frame is stored, so an
            // append rejected above (e.g. queue full) does not spend
            // its token.
            admission
                .record_success(&tag)
                .await
                .map_err(|e| HandlerError::InternalServerError(e.into()))?;
        }
        inner_status(StatusCode::OK)
    }

    /// Route GET /q/{id}?after=n: read a fixed-size page of frames
    /// starting at frame index n.
    ///
    /// The page always spans [`K_FRAMES_PER_RESPONSE`] frame slots, with
    /// unused slots zero-filled so the inner body length is constant. An
    /// all-zero slot cannot be mistaken for content: readers recognize
    /// their frames by HPKE trial decryption, which a zero-filled slot
    /// fails. The `x-pj-next` header carries the index to resume from,
    /// so a reader polls with `after` set to the last value it received.
    async fn get_queue(
        &self,
        queues: &QueueStore,
        id: &str,
        query: &str,
    ) -> Result<Response<Body>, HandlerError> {
        let Ok(id) = ShortId::from_str(id) else {
            return inner_status(StatusCode::BAD_REQUEST);
        };
        let Some(after) = parse_index_param(query, "after") else {
            return inner_status(StatusCode::BAD_REQUEST);
        };
        let frames = queues
            .read(&id, after, K_FRAMES_PER_RESPONSE)
            .await
            .map_err(|e| HandlerError::InternalServerError(e.into()))?;
        let next = after + frames.len() as u64;

        let mut page = Vec::with_capacity(K_FRAMES_PER_RESPONSE * FRAME_BYTES);
        for frame in &frames {
            page.extend_from_slice(frame);
        }
        page.resize(K_FRAMES_PER_RESPONSE * FRAME_BYTES, 0);

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(NEXT_INDEX_HEADER, next)
            .body(full(page))?)
    }

    /// Route POST /board: submit one blob, gated by admission control.
    ///
    /// The body is the configured admission material followed by the
    /// blob, at a fixed length so every submission looks identical on
    /// the wire. As with queue endpoints, client errors are
    /// inner statuses. A submission whose admission tag was already
    /// recorded is acknowledged without being stored again, so a client
    /// that never saw its response (e.g. an OHTTP retransmit) can retry
    /// without duplicating its entry, mirroring idempotent mailbox
    /// posts.
    async fn post_board(&self, body: Body) -> Result<Response<Body>, HandlerError> {
        let board = self.board.as_ref().expect("router guards on board presence");
        let submission = body
            .collect()
            .await
            .map_err(|e| HandlerError::InternalServerError(e.into()))?
            .to_bytes();
        if submission.len() != board.admission_bytes + BLOB_BYTES {
            return inner_status(StatusCode::BAD_REQUEST);
        }
        let tag = match board.admission.verify(&submission).await {
            Ok(tag) => tag,
            Err(Rejection::Malformed) => return inner_status(StatusCode::BAD_REQUEST),
            Err(Rejection::InsufficientWork) => return inner_status(StatusCode::TOO_MANY_REQUESTS),
            Err(Rejection::Unauthorized) => return inner_status(StatusCode::UNAUTHORIZED),
            Err(Rejection::Conflict) => return inner_status(StatusCode::CONFLICT),
            Err(Rejection::Unavailable) => return inner_status(StatusCode::SERVICE_UNAVAILABLE),
        };
        match board.admission.seen(&tag).await {
            Ok(false) => {}
            Ok(true) => return inner_status(StatusCode::OK),
            Err(e) => return Err(HandlerError::InternalServerError(e.into())),
        }
        match board.store.post(&submission[board.admission_bytes..]).await {
            Ok(_seq) => {}
            Err(BoardError::InvalidBlobSize(_)) => return inner_status(StatusCode::BAD_REQUEST),
            Err(BoardError::OverCapacity) => return inner_status(StatusCode::SERVICE_UNAVAILABLE),
            Err(BoardError::IO(e)) => return Err(HandlerError::InternalServerError(e.into())),
        }
        // Record the tag only now that the entry is stored, so a
        // submission rejected above (e.g. board full) can be retried
        // with the same proof.
        board
            .admission
            .record_success(&tag)
            .await
            .map_err(|e| HandlerError::InternalServerError(e.into()))?;
        inner_status(StatusCode::OK)
    }

    /// Route GET /board?since=n: read a fixed-size page of entries with
    /// sequence numbers at or above n.
    ///
    /// The page always spans [`K_BLOBS_PER_RESPONSE`] blob slots in
    /// sequence order, zero-filled past the last live entry; readers
    /// recognize entries addressed to them by trial decryption. The
    /// `x-pj-next` header carries the sequence number to resume from.
    /// Expired entries leave gaps in the sequence that readers cannot
    /// observe.
    async fn get_board(&self, query: &str) -> Result<Response<Body>, HandlerError> {
        let board = self.board.as_ref().expect("router guards on board presence");
        let Some(since) = parse_index_param(query, "since") else {
            return inner_status(StatusCode::BAD_REQUEST);
        };
        let entries = board
            .store
            .read(since, K_BLOBS_PER_RESPONSE)
            .await
            .map_err(|e| HandlerError::InternalServerError(e.into()))?;
        let next = entries.last().map(|(seq, _)| seq + 1).unwrap_or(since);

        let mut page = Vec::with_capacity(K_BLOBS_PER_RESPONSE * BLOB_BYTES);
        for (_seq, blob) in &entries {
            page.extend_from_slice(blob);
        }
        page.resize(K_BLOBS_PER_RESPONSE * BLOB_BYTES, 0);

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header(NEXT_INDEX_HEADER, next)
            .body(full(page))?)
    }

    /// Screen a V1 PSBT body against the address blocklist.
    ///
    /// Returns `Ok(())` if screening passes or is not configured.
    async fn check_v1_blocklist(&self, body_str: &str) -> Result<(), HandlerError> {
        if let Some(blocked) = self.v1.as_ref().and_then(|v| v.blocked_addresses.as_ref()) {
            let scripts = blocked.0.read().await;
            if !scripts.is_empty() {
                match screen_v1_addresses(body_str, &scripts) {
                    ScreenResult::Blocked => {
                        return Err(HandlerError::V1PsbtRejected(anyhow::anyhow!(
                            "blocked address in V1 PSBT"
                        )));
                    }
                    ScreenResult::Clean => {}
                    ScreenResult::ParseError(e) => warn!("Could not parse V1 PSBT: {e}"),
                }
            }
        }
        Ok(())
    }

    async fn put_payjoin_v1(&self, id: &str, body: Body) -> Result<Response<Body>, HandlerError> {
        let ok_response = Response::builder().status(StatusCode::OK).body(empty())?;
        let id = ShortId::from_str(id)?;
        let req = body
            .collect()
            .await
            .map_err(|e| HandlerError::InternalServerError(e.into()))?
            .to_bytes();
        if req.len() > V1_MAX_BUFFER_SIZE {
            return Err(HandlerError::PayloadTooLarge);
        }

        let body_str = std::str::from_utf8(&req).map_err(|e| HandlerError::BadRequest(e.into()))?;
        self.check_v1_blocklist(body_str).await?;

        match self.db.post_v1_response(&id, req.into()).await {
            Ok(_) => Ok(ok_response),
            Err(e) => Err(HandlerError::BadRequest(e.into())),
        }
    }

    async fn post_fallback_v1<B>(
        &self,
        id: &str,
        query: String,
        body: B,
    ) -> Result<Response<Body>, HandlerError>
    where
        B: axum::body::HttpBody<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let none_response = Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(full(V1_UNAVAILABLE_RES_JSON))?;
        let bad_request_body_res =
            Response::builder().status(StatusCode::BAD_REQUEST).body(full(V1_REJECT_RES_JSON))?;

        let body_bytes = match body.collect().await {
            Ok(bytes) => bytes.to_bytes(),
            Err(_) => return Ok(bad_request_body_res),
        };
        let body_str = match String::from_utf8(body_bytes.to_vec()) {
            Ok(body_str) => body_str,
            Err(_) => return Ok(bad_request_body_res),
        };
        self.check_v1_blocklist(&body_str).await?;

        let v2_compat_body = format!("{body_str}\n{query}");
        let id = ShortId::from_str(id)?;
        handle_peek(
            self.db.post_v1_request_and_wait_for_response(&id, v2_compat_body.into()).await,
            none_response,
        )
    }

    async fn handle_ohttp_gateway_get(&self, query: &str) -> Result<Response<Body>, HandlerError> {
        match query {
            "allowed_purposes" => Ok(self.get_ohttp_allowed_purposes().await),
            _ => self.get_ohttp_keys().await,
        }
    }

    async fn get_ohttp_keys(&self) -> Result<Response<Body>, HandlerError> {
        let ohttp_keys = self
            .ohttp
            .config()
            .encode()
            .map_err(|e| HandlerError::InternalServerError(e.into()))?;
        let mut res = Response::new(full(ohttp_keys));
        res.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/ohttp-keys"));
        Ok(res)
    }

    async fn get_ohttp_allowed_purposes(&self) -> Response<Body> {
        // Encode the magic string in the same format as a TLS ALPN protocol list (a
        // U16BE length encoded list of U8 length encoded strings).
        //
        // The string is just "BIP77" followed by a UUID, that signals to relays
        // that this OHTTP gateway will accept any requests associated with this
        // purpose.
        let mut res = Response::new(full(Bytes::from_static(
            b"\x00\x01\x2aBIP77 454403bb-9f7b-4385-b31f-acd2dae20b7e",
        )));
        res.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("application/x-ohttp-allowed-purposes"));
        res
    }

    async fn health_check(&self) -> Result<Response<Body>, HandlerError> {
        let versions = if self.v1.is_some() { "[1,2]" } else { "[2]" };
        let body = format!(r#"{{"versions":{versions}}}"#);
        let mut res = Response::new(full(body));
        res.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        Ok(res)
    }
}

/// An empty inner response carrying only a status code, for handlers
/// whose errors must remain encapsulated.
fn inner_status(status: StatusCode) -> Result<Response<Body>, HandlerError> {
    Ok(Response::builder().status(status).body(empty())?)
}

/// Parse a non-negative integer query parameter: zero when absent,
/// `None` when present but malformed.
fn parse_index_param(query: &str, name: &str) -> Option<u64> {
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix(name).and_then(|rest| rest.strip_prefix('=')) {
            return value.parse().ok();
        }
    }
    Some(0)
}

fn handle_peek<E: SendableError>(
    result: Result<Arc<Vec<u8>>, DbError<E>>,
    timeout_response: Response<Body>,
) -> Result<Response<Body>, HandlerError> {
    match result {
        Ok(payload) => Ok(Response::new(full((*payload).clone()))), // TODO Bytes instead of Arc<Vec<u8>>
        Err(e) => match e {
            DbError::Operational(err) => {
                error!("Storage error: {err}");
                Err(HandlerError::InternalServerError(anyhow::Error::msg("Internal server error")))
            }
            DbError::Timeout(_) => Ok(timeout_response),
            DbError::OverCapacity => Err(HandlerError::ServiceUnavailable(anyhow::Error::msg(
                "mailbox storage at capacity",
            ))),
            DbError::AlreadyRead => Ok(timeout_response),
            DbError::V1SenderUnavailable => Err(HandlerError::SenderGone(anyhow::Error::msg(
                "Sender is unavailable try a new request",
            ))),
        },
    }
}

fn landing_page_html() -> String {
    const TEMPLATE: &str = include_str!("../static/index.html");
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    let version_string = match option_env!("GIT_COMMIT") {
        Some(commit) => format!("payjoin-mailroom-v{VERSION} @ {commit}"),
        None => format!("payjoin-mailroom-v{VERSION}"),
    };
    TEMPLATE.replace("{{VERSION_STRING}}", &version_string)
}

async fn handle_directory_home_path() -> Result<Response<Body>, HandlerError> {
    let html = landing_page_html();
    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/html")
        .body(full(html))?)
}

#[derive(Debug)]
enum HandlerError {
    PayloadTooLarge,
    InternalServerError(anyhow::Error),
    ServiceUnavailable(anyhow::Error),
    SenderGone(anyhow::Error),
    OhttpKeyRejection(anyhow::Error),
    BadRequest(anyhow::Error),
    /// V1 PSBT rejected — returns the BIP78 `original-psbt-rejected` error.
    V1PsbtRejected(anyhow::Error),
    Forbidden(anyhow::Error),
}

impl HandlerError {
    fn to_response(&self) -> Response<Body> {
        let mut res = Response::new(empty());
        match self {
            HandlerError::PayloadTooLarge => *res.status_mut() = StatusCode::PAYLOAD_TOO_LARGE,
            HandlerError::InternalServerError(e) => {
                error!("Internal server error: {}", e);
                *res.status_mut() = StatusCode::INTERNAL_SERVER_ERROR
            }
            HandlerError::ServiceUnavailable(e) => {
                error!("Service temporarily unavailable: {}", e);
                *res.status_mut() = StatusCode::SERVICE_UNAVAILABLE
            }
            HandlerError::SenderGone(e) => {
                error!("Sender gone: {}", e);
                *res.status_mut() = StatusCode::GONE
            }
            HandlerError::OhttpKeyRejection(e) => {
                const OHTTP_KEY_REJECTION_RES_JSON: &str = r#"{"type":"https://iana.org/assignments/http-problem-types#ohttp-key", "title": "key identifier unknown"}"#;
                warn!("Bad request: Key configuration rejected: {}", e);
                *res.status_mut() = StatusCode::BAD_REQUEST;
                res.headers_mut()
                    .insert(CONTENT_TYPE, HeaderValue::from_static("application/problem+json"));
                *res.body_mut() = full(OHTTP_KEY_REJECTION_RES_JSON);
            }
            HandlerError::BadRequest(e) => {
                warn!("Bad request: {}", e);
                *res.status_mut() = StatusCode::BAD_REQUEST
            }
            HandlerError::V1PsbtRejected(e) => {
                warn!("PSBT rejected: {}", e);
                *res.status_mut() = StatusCode::BAD_REQUEST;
                *res.body_mut() = full(V1_REJECT_RES_JSON);
            }
            HandlerError::Forbidden(e) => {
                warn!("Forbidden: {}", e);
                *res.status_mut() = StatusCode::FORBIDDEN
            }
        }
        res
    }
}

impl From<axum::http::Error> for HandlerError {
    fn from(e: axum::http::Error) -> Self { HandlerError::InternalServerError(e.into()) }
}

impl From<ShortIdError> for HandlerError {
    fn from(_: ShortIdError) -> Self {
        HandlerError::BadRequest(anyhow::anyhow!("mailbox ID must be 13 bech32 characters"))
    }
}

fn not_found() -> Response<Body> {
    let mut res = Response::default();
    *res.status_mut() = StatusCode::NOT_FOUND;
    res
}

fn empty() -> Body { Body::empty() }

fn full<T: Into<Bytes>>(chunk: T) -> Body { Body::from(chunk.into()) }

enum ScreenResult {
    Blocked,
    Clean,
    ParseError(String),
}

fn screen_v1_addresses(
    body: &str,
    blocked: &std::collections::HashSet<bitcoin::ScriptBuf>,
) -> ScreenResult {
    use bitcoin::base64::prelude::{Engine, BASE64_STANDARD};
    use bitcoin::psbt::Psbt;

    let psbt_bytes = match BASE64_STANDARD.decode(body) {
        Ok(b) => b,
        Err(e) => return ScreenResult::ParseError(format!("base64 decode: {e}")),
    };
    let psbt = match Psbt::deserialize(&psbt_bytes) {
        Ok(p) => p,
        Err(e) => return ScreenResult::ParseError(format!("PSBT deserialize: {e}")),
    };

    // Check output scripts
    for txout in &psbt.unsigned_tx.output {
        if blocked.contains(&txout.script_pubkey) {
            return ScreenResult::Blocked;
        }
    }

    // Check input scripts from witness_utxo and non_witness_utxo
    for (i, input) in psbt.inputs.iter().enumerate() {
        if let Some(ref utxo) = input.witness_utxo {
            if blocked.contains(&utxo.script_pubkey) {
                return ScreenResult::Blocked;
            }
        }
        if let Some(ref tx) = input.non_witness_utxo {
            if let Some(prev_out) = psbt.unsigned_tx.input.get(i) {
                if let Some(txout) = tx.output.get(prev_out.previous_output.vout as usize) {
                    if blocked.contains(&txout.script_pubkey) {
                        return ScreenResult::Blocked;
                    }
                }
            }
        }
    }
    ScreenResult::Clean
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use http_body_util::BodyExt;
    use payjoin::directory::ShortId;

    use super::*;
    use crate::db::FilesDb;
    use crate::ohttp_relay::SentinelTag;

    async fn test_service(v1: Option<V1>) -> Service<FilesDb> {
        let dir = tempfile::tempdir().expect("tempdir");
        let db = FilesDb::init(
            Duration::from_millis(100),
            dir.keep(),
            Duration::from_secs(60 * 60 * 24 * 7),
        )
        .await
        .expect("db init");
        let ohttp: ohttp::Server =
            crate::key_config::gen_ohttp_server_config().expect("ohttp config").into();
        Service::new(db, ohttp, SentinelTag::new([0u8; 32]), v1)
    }

    /// A valid ShortId encoded as bech32 for use in URL paths.
    fn valid_short_id_path() -> String {
        let id = ShortId([0u8; 8]);
        id.to_string()
    }

    async fn collect_body(res: Response<Body>) -> (StatusCode, String) {
        let (parts, body) = res.into_parts();
        let bytes = body.collect().await.unwrap().to_bytes();
        (parts.status, String::from_utf8(bytes.to_vec()).unwrap())
    }

    // V1 routing

    #[tokio::test]
    async fn post_v1_when_disabled_returns_version_unsupported() {
        let mut svc = test_service(None).await;
        let id = valid_short_id_path();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://localhost/{id}"))
            .body(Body::from("base64-psbt"))
            .unwrap();

        let res = tower::Service::call(&mut svc, req).await.unwrap();
        let (status, body) = collect_body(res).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, V1_VERSION_UNSUPPORTED_RES_JSON);
    }

    #[tokio::test]
    async fn post_v1_with_invalid_body_returns_reject() {
        let mut svc = test_service(Some(V1::new(None))).await;
        let id = valid_short_id_path();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://localhost/{id}"))
            .body(Body::from(vec![0xFF, 0xFE]))
            .unwrap();

        let res = tower::Service::call(&mut svc, req).await.unwrap();
        let (status, body) = collect_body(res).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, V1_REJECT_RES_JSON);
    }

    #[tokio::test]
    async fn post_v1_with_no_receiver_returns_unavailable() {
        let mut svc = test_service(Some(V1::new(None))).await;
        let id = valid_short_id_path();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://localhost/{id}"))
            .body(Body::from("base64-psbt"))
            .unwrap();

        let res = tower::Service::call(&mut svc, req).await.unwrap();
        let (status, body) = collect_body(res).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body, V1_UNAVAILABLE_RES_JSON);
    }

    // Address screening

    fn make_test_psbt_base64(output_address: &str) -> String {
        use bitcoin::base64::prelude::{Engine, BASE64_STANDARD};
        use bitcoin::psbt::Psbt;
        use bitcoin::{Amount, Transaction, TxIn, TxOut};

        let addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
            output_address.parse().expect("valid address");
        let script_pubkey = addr.assume_checked().script_pubkey();

        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![TxOut { value: Amount::from_sat(50_000), script_pubkey }],
        };

        let psbt = Psbt::from_unsigned_tx(tx).expect("valid psbt");
        BASE64_STANDARD.encode(psbt.serialize())
    }

    fn addr_to_script(address: &str) -> bitcoin::ScriptBuf {
        let addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
            address.parse().expect("valid address");
        addr.assume_checked().script_pubkey()
    }

    #[tokio::test]
    async fn post_v1_with_blocked_address_returns_bad_request() {
        let blocked_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let blocked = BlockedAddresses::from_address_lines(blocked_addr);
        let mut svc = test_service(Some(V1::new(Some(blocked)))).await;
        let id = valid_short_id_path();
        let psbt_b64 = make_test_psbt_base64(blocked_addr);
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("http://localhost/{id}"))
            .body(Body::from(psbt_b64))
            .unwrap();

        let res = tower::Service::call(&mut svc, req).await.unwrap();
        let (status, body) = collect_body(res).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body, V1_REJECT_RES_JSON);
    }

    #[test]
    fn screen_blocks_blocked_output_address() {
        let blocked_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let blocked = std::collections::HashSet::from([addr_to_script(blocked_addr)]);

        let psbt_b64 = make_test_psbt_base64(blocked_addr);
        assert!(matches!(screen_v1_addresses(&psbt_b64, &blocked), ScreenResult::Blocked));
    }

    #[test]
    fn screen_allows_clean_psbt() {
        let clean_addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let blocked = std::collections::HashSet::new(); // empty
        let psbt_b64 = make_test_psbt_base64(clean_addr);
        assert!(matches!(screen_v1_addresses(&psbt_b64, &blocked), ScreenResult::Clean));
    }

    #[test]
    fn screen_allows_non_blocked_address() {
        let addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let blocked =
            std::collections::HashSet::from([addr_to_script("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy")]);

        let psbt_b64 = make_test_psbt_base64(addr);
        assert!(matches!(screen_v1_addresses(&psbt_b64, &blocked), ScreenResult::Clean));
    }

    #[test]
    fn screen_parse_error_on_invalid_base64() {
        let blocked =
            std::collections::HashSet::from([addr_to_script("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")]);
        assert!(matches!(
            screen_v1_addresses("not-valid-base64!!!", &blocked),
            ScreenResult::ParseError(_)
        ));
    }

    #[test]
    fn screen_parse_error_on_invalid_psbt() {
        use bitcoin::base64::prelude::{Engine, BASE64_STANDARD};
        let blocked =
            std::collections::HashSet::from([addr_to_script("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")]);
        let bad_psbt = BASE64_STANDARD.encode(b"not a psbt");
        assert!(matches!(screen_v1_addresses(&bad_psbt, &blocked), ScreenResult::ParseError(_)));
    }

    #[test]
    fn screen_blocks_bech32_address() {
        let addr = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
        let blocked = std::collections::HashSet::from([addr_to_script(addr)]);

        let psbt_b64 = make_test_psbt_base64(addr);
        assert!(matches!(screen_v1_addresses(&psbt_b64, &blocked), ScreenResult::Blocked));
    }

    // Health check

    #[tokio::test]
    async fn health_check_without_v1() {
        let mut svc = test_service(None).await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://localhost/health")
            .body(Body::empty())
            .unwrap();

        let res = tower::Service::call(&mut svc, req).await.unwrap();
        assert_eq!(res.headers().get(CONTENT_TYPE).unwrap(), "application/json");
        let (status, body) = collect_body(res).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, r#"{"versions":[2]}"#);
    }

    #[tokio::test]
    async fn health_check_with_v1() {
        let mut svc = test_service(Some(V1::new(None))).await;
        let req = Request::builder()
            .method(Method::GET)
            .uri("http://localhost/health")
            .body(Body::empty())
            .unwrap();

        let res = tower::Service::call(&mut svc, req).await.unwrap();
        assert_eq!(res.headers().get(CONTENT_TYPE).unwrap(), "application/json");
        let (status, body) = collect_body(res).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, r#"{"versions":[1,2]}"#);
    }

    // Landing page

    #[test]
    fn landing_page_contains_version() {
        let html = landing_page_html();
        assert!(!html.contains("{{VERSION_STRING}}"));
    }

    // MetricsDb decorator

    #[tokio::test]
    async fn post_mailbox_increments_v2_db_entry_metric() {
        use opentelemetry_sdk::metrics::{
            InMemoryMetricExporter, PeriodicReader, SdkMeterProvider,
        };

        use crate::db::MetricsDb;
        use crate::metrics::{MetricsService, DB_ENTRIES};

        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let metrics = MetricsService::new(Some(provider.clone()));

        let dir = tempfile::tempdir().expect("tempdir");
        let db = FilesDb::init(
            Duration::from_millis(100),
            dir.keep(),
            Duration::from_secs(60 * 60 * 24 * 7),
        )
        .await
        .expect("db init");
        let db = MetricsDb::new(db, metrics);
        let ohttp: ohttp::Server =
            crate::key_config::gen_ohttp_server_config().expect("ohttp config").into();
        let svc = Service::new(db, ohttp, SentinelTag::new([0u8; 32]), None);

        let id = valid_short_id_path();
        let res = svc
            .post_mailbox(&id, Body::from(b"small payload under 65k limit".to_vec()))
            .await
            .expect("post_mailbox should succeed");
        assert_eq!(res.status(), StatusCode::OK);

        provider.force_flush().expect("flush failed");
        let finished = exporter.get_finished_metrics().expect("metrics");
        let db_metric = finished
            .iter()
            .flat_map(|rm| rm.scope_metrics())
            .flat_map(|sm| sm.metrics())
            .find(|m| m.name() == DB_ENTRIES)
            .expect("missing db_entries_total metric");

        use opentelemetry::KeyValue;
        use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};

        // This checks that  counter value is 1 as post_mailbox was called once
        // Also confirms the v2 label is recorded
        match db_metric.data() {
            AggregatedMetrics::U64(MetricData::Sum(sum)) => {
                let points: Vec<_> = sum.data_points().collect();
                assert_eq!(points.len(), 1, "expected exactly one data point");
                assert_eq!(points[0].value(), 1, "expected counter value of 1");
                let attrs: Vec<_> = points[0].attributes().collect();
                assert!(
                    attrs.contains(&&KeyValue::new("version", "2")),
                    "expected version=2 attribute"
                );
            }
            other => panic!("expected U64 Sum, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn post_mailbox_records_short_id_cardinality() {
        use opentelemetry_sdk::metrics::{
            InMemoryMetricExporter, PeriodicReader, SdkMeterProvider,
        };

        use crate::db::MetricsDb;
        use crate::metrics::{MetricsService, UNIQUE_SHORT_IDS};

        let exporter = InMemoryMetricExporter::default();
        let reader = PeriodicReader::builder(exporter.clone()).build();
        let provider = SdkMeterProvider::builder().with_reader(reader).build();
        let metrics = MetricsService::new(Some(provider.clone()));

        let dir = tempfile::tempdir().expect("tempdir");
        let db = FilesDb::init(
            Duration::from_millis(100),
            dir.keep(),
            Duration::from_secs(60 * 60 * 24 * 7),
        )
        .await
        .expect("db init");
        let db = MetricsDb::new(db, metrics);
        let ohttp: ohttp::Server =
            crate::key_config::gen_ohttp_server_config().expect("ohttp config").into();
        let svc = Service::new(db, ohttp, SentinelTag::new([0u8; 32]), None);

        let id = valid_short_id_path();
        let res = svc
            .post_mailbox(&id, Body::from(b"payload".to_vec()))
            .await
            .expect("post_mailbox should succeed");
        assert_eq!(res.status(), StatusCode::OK);

        provider.force_flush().expect("flush failed");
        let finished = exporter.get_finished_metrics().expect("metrics");
        let gauge = finished
            .iter()
            .flat_map(|rm| rm.scope_metrics())
            .flat_map(|sm| sm.metrics())
            .find(|m| m.name() == UNIQUE_SHORT_IDS)
            .expect("missing unique_short_ids metric");

        use opentelemetry::KeyValue;
        use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData};

        match gauge.data() {
            AggregatedMetrics::U64(MetricData::Gauge(g)) => {
                let points: Vec<_> = g.data_points().collect();
                assert!(!points.is_empty(), "expected at least one data point");
                let hourly = points.iter().find(|dp| {
                    dp.attributes().any(|kv| kv == &KeyValue::new("interval", "hourly"))
                });
                assert!(hourly.is_some(), "expected hourly data point");
                assert!(hourly.unwrap().value() >= 1, "expected at least 1 unique short ID");
            }
            other => panic!("expected U64 Gauge, got {other:?}"),
        }
    }
}
