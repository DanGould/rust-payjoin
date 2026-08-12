//! Receive many Payjoin proposals over one long-lived static session.
//!
//! A static session is a long-lived payment endpoint: one receiver key and
//! one directory queue serve many independent senders, in contrast to a
//! standard v2 session, which dedicates a fresh key, mailbox, and
//! expiration to a single payment. A static session has no expiration by
//! design. The endpoint is published once (for example on a donation page)
//! and served indefinitely, and any deadline on an individual payment is
//! the sender's policy rather than a property of the endpoint.
//!
//! The [`StaticReceiver`] does not itself progress through the proposal
//! typestates. It polls the directory queue derived from the session's
//! receiver key, and every valid message A retrieved yields an
//! [`InboundProposal`]: a per-payment sub-session that seeds its own event
//! log and then follows the standard [`Receiver`] flow
//! (validation, contribution, reply) while the static session keeps
//! polling for other senders.
//!
//! Because the queue's mailbox ID is derived from the receiver key
//! published in the payjoin URI, anyone can address it. A frame that fails
//! decryption is therefore an expected condition — another client's frame,
//! padding, or spam — and is skipped and remembered, in contrast to a
//! standard session, whose mailbox is derived from an unguessable
//! per-session key, making undecryptable content there an integrity
//! signal that fatally closes the session.

use std::collections::HashSet;
use std::fmt;

use bitcoin::{Address, Amount, FeeRate};
use serde::{Deserialize, Serialize};

use super::{
    deserialize_address_assume_checked, original_payload_from_str, CreateRequestError, Receiver,
    SessionContext, SessionEvent, UncheckedOriginalPayload, TWENTY_FOUR_HOURS_DEFAULT_EXPIRATION,
};
use crate::core::Url;
use crate::directory::{QUEUE_FRAME_BYTES, QUEUE_NEXT_HEADER, QUEUE_PAGE_BYTES};
use crate::error::{InternalReplayError, ReplayError};
use crate::hpke::{decrypt_message_a, HpkeKeyPair, HpkePublicKey};
use crate::ohttp::{
    ohttp_decapsulate, ohttp_encapsulate, OhttpEncapsulationError, OhttpKeys, OhttpResponse,
};
use crate::output_substitution::OutputSubstitution;
use crate::persist::{
    ApiError, AsyncSessionPersister, InternalPersistedError, NextStateTransition, PersistedError,
    SessionPersister, TerminalTransition,
};
use crate::receive::OriginalPayload;
use crate::time::Time;
use crate::uri::ShortId;
use crate::{ImplementationError, IntoUrl, IntoUrlError, Request};

/// Data shared by a static session and every sub-session it spawns.
///
/// Compared to a standard [`SessionContext`] there is no expiration (the
/// endpoint is long-lived) and no reply key (each retrieved proposal
/// carries its own).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticSessionContext {
    #[serde(deserialize_with = "deserialize_address_assume_checked")]
    address: Address,
    directory: Url,
    ohttp_keys: OhttpKeys,
    amount: Option<Amount>,
    receiver_key: HpkeKeyPair,
    max_fee_rate: FeeRate,
}

impl StaticSessionContext {
    /// The queue ID senders derive from the receiver key in the payjoin URI.
    fn queue_id(&self) -> ShortId { ShortId::from(self.receiver_key.public_key()) }
}

/// Builds a [`StaticReceiver`].
#[derive(Debug, Clone)]
pub struct StaticReceiverBuilder(StaticSessionContext);

impl StaticReceiverBuilder {
    /// Creates a new [`StaticReceiverBuilder`] for a static session serving
    /// `address` through the given Payjoin directory.
    ///
    /// Unlike [`ReceiverBuilder::new`](super::ReceiverBuilder::new), the
    /// receiver key is supplied by the caller rather than freshly
    /// generated: the key and the queue derived from it are the long-lived
    /// identity of the payment endpoint, so the caller owns its storage and
    /// rotation. There is also no expiration to configure; see the module
    /// documentation for why static sessions do not expire.
    ///
    /// Note that `address` is shared with every sender polling this
    /// endpoint. Applications that want distinct outputs per payment should
    /// substitute the receiver output while processing each proposal (see
    /// [`Receiver<WantsOutputs>`](super::Receiver#impl-Receiver<WantsOutputs>)).
    pub fn new(
        address: Address,
        directory: impl IntoUrl,
        ohttp_keys: OhttpKeys,
        receiver_key: HpkeKeyPair,
    ) -> Result<Self, IntoUrlError> {
        let directory = directory.into_url()?;
        Ok(Self(StaticSessionContext {
            address,
            directory,
            ohttp_keys,
            amount: None,
            receiver_key,
            max_fee_rate: FeeRate::BROADCAST_MIN,
        }))
    }

    pub fn with_amount(self, amount: Amount) -> Self {
        Self(StaticSessionContext { amount: Some(amount), ..self.0 })
    }

    /// Set the maximum effective fee rate the receiver is willing to pay
    /// for their own input/output contributions in each sub-session.
    pub fn with_max_fee_rate(self, max_fee_rate: FeeRate) -> Self {
        Self(StaticSessionContext { max_fee_rate, ..self.0 })
    }

    pub fn build(self) -> NextStateTransition<StaticSessionEvent, StaticReceiver> {
        NextStateTransition::success(
            StaticSessionEvent::Created(self.0.clone()),
            StaticReceiver { context: self.0, cursor: 0, seen: HashSet::new() },
        )
    }
}

/// A static session receiver: polls the directory queue for message A
/// frames and dispatches each valid one into its own per-payment
/// sub-session.
///
/// Unlike [`Receiver`], this type does not move through
/// typestates. Polling never consumes the session; it only advances the
/// queue cursor and the set of frames already handled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticReceiver {
    context: StaticSessionContext,
    cursor: u64,
    seen: HashSet<FrameHash>,
}

impl StaticReceiver {
    /// Build the static session's payjoin URI: receiver key and OHTTP keys
    /// in the fragment, and no expiration.
    pub fn pj_uri(&self) -> crate::PjUri { pj_uri(&self.context) }

    /// Construct an OHTTP encapsulated GET request polling the directory
    /// queue for frames after the current cursor.
    ///
    /// There is deliberately no expiration check here; a static session
    /// polls for as long as the application keeps it open.
    pub fn create_poll_request(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, OhttpResponse), CreateRequestError> {
        let target = self.queue_endpoint();
        let (body, ohttp_ctx) =
            ohttp_encapsulate(&self.context.ohttp_keys, "GET", target.as_str(), None)
                .map_err(super::InternalCreateRequestError::OhttpEncapsulation)?;
        let req = Request::new_v2(&full_relay_url(&self.context.directory, ohttp_relay)?, &body);
        Ok((req, OhttpResponse::new(ohttp_ctx)))
    }

    /// Process a queue poll response.
    ///
    /// Each of the page's frames is identified by HPKE trial decryption:
    /// zero-filled padding and frames already handled in earlier polls are
    /// ignored, frames that fail decryption or carry a malformed payload
    /// are recorded as skipped, and each valid message A becomes an
    /// [`InboundProposal`]. Multiple proposals from one page are returned
    /// in frame order.
    ///
    /// Nothing in a poll response is fatal to the session; errors are
    /// transient and the session polls again.
    pub fn process_response(mut self, body: &[u8], context: OhttpResponse) -> StaticPollTransition {
        let (next, page) = match process_queue_response(body, context) {
            Ok(ok) => ok,
            Err(e) => return StaticPollTransition::transient(e, self),
        };

        let mut events = Vec::new();
        let mut proposals = Vec::new();
        for frame in page.chunks_exact(QUEUE_FRAME_BYTES) {
            // An all-zero slot is page padding, not a message.
            if frame.iter().all(|&b| b == 0) {
                continue;
            }
            let frame_hash = FrameHash::from_frame(frame);
            // Deduplicate by ciphertext across polls: directory delivery is
            // at-least-once, and replaying an already-handled frame would
            // spawn a duplicate sub-session for the same payment.
            if !self.seen.insert(frame_hash) {
                continue;
            }
            match decrypt_message_a(frame, self.context.receiver_key.secret_key()) {
                // Not addressed to us: another client's frame or spam.
                Err(_) => events.push(StaticSessionEvent::SkippedUndecryptable(frame_hash)),
                Ok((payload, reply_key)) => match std::str::from_utf8(&payload)
                    .ok()
                    .and_then(|payload| original_payload_from_str(payload).ok())
                {
                    Some(original) => {
                        events.push(StaticSessionEvent::RetrievedProposal {
                            frame_hash,
                            original: original.clone(),
                            reply_key: reply_key.clone(),
                        });
                        proposals.push(InboundProposal {
                            context: self.context.clone(),
                            original,
                            reply_key,
                        });
                    }
                    // Addressed to us but not a well-formed Original PSBT
                    // payload; remember it so it is not re-parsed each poll.
                    None => events.push(StaticSessionEvent::SkippedInvalidPayload(frame_hash)),
                },
            }
        }
        if next != self.cursor {
            events.push(StaticSessionEvent::CursorAdvanced(next));
            self.cursor = next;
        }
        StaticPollTransition::progress(events, self, proposals)
    }

    /// Close the static session, e.g. when rotating the endpoint to a new
    /// receiver key.
    pub fn close(self) -> TerminalTransition<StaticSessionEvent, ()> {
        TerminalTransition::new(StaticSessionEvent::Closed, ())
    }

    fn queue_endpoint(&self) -> Url {
        let mut url = self.context.directory.clone();
        {
            let mut path_segments =
                url.path_segments_mut().expect("Payjoin Directory URL cannot be a base");
            path_segments.push("q");
            path_segments.push(&self.context.queue_id().to_string());
        }
        url.query_pairs_mut().append_pair("after", &self.cursor.to_string());
        url
    }
}

/// Gets the payjoin URI for a static session context.
fn pj_uri(context: &StaticSessionContext) -> crate::PjUri {
    use crate::uri::PayjoinExtras;
    let pj_param = crate::uri::PjParam::V2Static(crate::uri::v2::StaticPjParam::new(
        context.directory.clone(),
        context.queue_id(),
        context.ohttp_keys.clone(),
        context.receiver_key.public_key().clone(),
    ));
    let extras = PayjoinExtras { pj_param, output_substitution: OutputSubstitution::Disabled };
    let mut uri = crate::uri::PjUri::from_extras(context.address.clone(), extras);
    if let Some(amount) = context.amount {
        uri.set_amount(amount);
    }
    uri
}

fn full_relay_url(
    directory: &Url,
    ohttp_relay: impl IntoUrl,
) -> Result<Url, crate::into_url::Error> {
    let relay_base = ohttp_relay.into_url()?;

    // Only reveal scheme and authority to the relay
    let directory_base = directory.join("/")?;

    // Append that information as a path to the relay URL
    Ok(relay_base.join(&format!("/{directory_base}"))?)
}

/// SHA-256 of a queue frame's ciphertext.
///
/// Used only as a deduplication identifier: it names a frame the session
/// has already handled so redelivery across polls is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FrameHash([u8; 32]);

impl FrameHash {
    fn from_frame(frame: &[u8]) -> Self {
        use bitcoin::hashes::{sha256, Hash};
        Self(sha256::Hash::hash(frame).to_byte_array())
    }
}

/// A proposal retrieved over a static session, ready to become its own
/// per-payment receive session.
#[derive(Debug, Clone, PartialEq)]
pub struct InboundProposal {
    context: StaticSessionContext,
    original: OriginalPayload,
    reply_key: HpkePublicKey,
}

impl InboundProposal {
    /// Seed a fresh event log for this proposal and return the standard
    /// receiver session that drives it.
    ///
    /// The log is written with the same two events a standard session
    /// records before validation (session creation and original payload
    /// retrieval), so [`replay_event_log`](super::replay_event_log) replays
    /// it like any other session. The sub-session carries the static
    /// session's long-lived receiver key, because the sender encrypted to
    /// that key and expects the reply authenticated by it, and a fresh
    /// 24-hour expiration: the parent endpoint never expires, but an
    /// individual payment's validation and reply should not stay live
    /// indefinitely.
    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<Receiver<UncheckedOriginalPayload>, P::InternalStorageError>
    where
        P: SessionPersister<SessionEvent = SessionEvent>,
    {
        let (context, original, reply_key) = self.into_sub_session_parts();
        persister.save_event(SessionEvent::Created(context.clone()))?;
        persister.save_event(SessionEvent::RetrievedOriginalPayload {
            original: original.clone(),
            reply_key: Some(reply_key.clone()),
        })?;
        Ok(Receiver {
            state: UncheckedOriginalPayload { original },
            session_context: SessionContext { reply_key: Some(reply_key), ..context },
        })
    }

    /// Async version of [`InboundProposal::save`].
    pub async fn save_async<P>(
        self,
        persister: &P,
    ) -> Result<Receiver<UncheckedOriginalPayload>, P::InternalStorageError>
    where
        P: AsyncSessionPersister<SessionEvent = SessionEvent>,
    {
        let (context, original, reply_key) = self.into_sub_session_parts();
        persister.save_event(SessionEvent::Created(context.clone())).await?;
        persister
            .save_event(SessionEvent::RetrievedOriginalPayload {
                original: original.clone(),
                reply_key: Some(reply_key.clone()),
            })
            .await?;
        Ok(Receiver {
            state: UncheckedOriginalPayload { original },
            session_context: SessionContext { reply_key: Some(reply_key), ..context },
        })
    }

    fn into_sub_session_parts(self) -> (SessionContext, OriginalPayload, HpkePublicKey) {
        let context = SessionContext {
            address: self.context.address,
            directory: self.context.directory,
            ohttp_keys: self.context.ohttp_keys,
            expiration: Time::from_now(TWENTY_FOUR_HOURS_DEFAULT_EXPIRATION)
                .expect("Default expiration time should be representable as u32 unix time"),
            amount: self.context.amount,
            receiver_key: self.context.receiver_key,
            reply_key: None,
            max_fee_rate: self.context.max_fee_rate,
        };
        (context, self.original, self.reply_key)
    }
}

/// The result of processing one queue poll response.
///
/// On success, persisting saves one event per handled frame plus a cursor
/// advance, and yields the updated [`StaticReceiver`] together with any
/// retrieved [`InboundProposal`]s. All failures are transient: nothing is
/// persisted and the returned session polls again.
#[must_use = "a transition must be persisted with .save() to advance the session"]
pub struct StaticPollTransition(Result<PollProgress, (StaticPollError, Box<StaticReceiver>)>);

struct PollProgress {
    events: Vec<StaticSessionEvent>,
    next_state: StaticReceiver,
    proposals: Vec<InboundProposal>,
}

impl StaticPollTransition {
    fn progress(
        events: Vec<StaticSessionEvent>,
        next_state: StaticReceiver,
        proposals: Vec<InboundProposal>,
    ) -> Self {
        Self(Ok(PollProgress { events, next_state, proposals }))
    }

    fn transient(error: StaticPollError, current_state: StaticReceiver) -> Self {
        Self(Err((error, Box::new(current_state))))
    }

    /// Persist the poll outcome and return the live session and retrieved
    /// proposals.
    ///
    /// Events are appended one at a time with the cursor advance last, so a
    /// crash mid-save leaves the cursor unadvanced and the next poll simply
    /// re-fetches the same page; already-persisted frame events deduplicate
    /// the frames handled before the crash. Retrieved proposals are also
    /// persisted in the events, so one lost to a crash before
    /// [`InboundProposal::save`] can be recovered from
    /// [`StaticSessionHistory::proposals`].
    #[allow(clippy::type_complexity)]
    pub fn save<P>(
        self,
        persister: &P,
    ) -> Result<
        (StaticReceiver, Vec<InboundProposal>),
        PersistedError<StaticPollError, P::InternalStorageError, (), Box<StaticReceiver>>,
    >
    where
        P: SessionPersister<SessionEvent = StaticSessionEvent>,
    {
        match self.0 {
            Ok(PollProgress { events, next_state, proposals }) => {
                for event in events {
                    persister.save_event(event).map_err(InternalPersistedError::Storage)?;
                }
                Ok((next_state, proposals))
            }
            Err((error, current_state)) =>
                Err(InternalPersistedError::Api(ApiError::Transient(error, current_state)).into()),
        }
    }

    /// Async version of [`StaticPollTransition::save`].
    #[allow(clippy::type_complexity)]
    pub async fn save_async<P>(
        self,
        persister: &P,
    ) -> Result<
        (StaticReceiver, Vec<InboundProposal>),
        PersistedError<StaticPollError, P::InternalStorageError, (), Box<StaticReceiver>>,
    >
    where
        P: AsyncSessionPersister<SessionEvent = StaticSessionEvent>,
    {
        match self.0 {
            Ok(PollProgress { events, next_state, proposals }) => {
                for event in events {
                    persister.save_event(event).await.map_err(InternalPersistedError::Storage)?;
                }
                Ok((next_state, proposals))
            }
            Err((error, current_state)) =>
                Err(InternalPersistedError::Api(ApiError::Transient(error, current_state)).into()),
        }
    }
}

/// Error processing a queue poll response. Always transient for the
/// session.
#[derive(Debug)]
pub struct StaticPollError(InternalStaticPollError);

#[derive(Debug)]
pub(crate) enum InternalStaticPollError {
    /// The response could not be decapsulated.
    Decapsulation(OhttpEncapsulationError),
    /// The directory responded with an unexpected status code.
    UnexpectedStatusCode(http::StatusCode),
    /// The response carried no parseable next-cursor header.
    MissingNextCursor,
    /// The response body is not exactly one queue page.
    UnexpectedPageSize(usize),
}

impl fmt::Display for StaticPollError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use InternalStaticPollError::*;
        match &self.0 {
            Decapsulation(e) => write!(f, "OHTTP decapsulation error: {e}"),
            UnexpectedStatusCode(status) => write!(f, "Unexpected status code: {status}"),
            MissingNextCursor =>
                write!(f, "Response carries no parseable {QUEUE_NEXT_HEADER} header"),
            UnexpectedPageSize(size) =>
                write!(f, "Unexpected page size {size}, expected {QUEUE_PAGE_BYTES} bytes"),
        }
    }
}

impl std::error::Error for StaticPollError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            InternalStaticPollError::Decapsulation(e) => Some(e),
            _ => None,
        }
    }
}

impl From<InternalStaticPollError> for StaticPollError {
    fn from(e: InternalStaticPollError) -> Self { StaticPollError(e) }
}

/// Decapsulate a queue poll response into the next cursor and the page
/// body.
///
/// Unlike mailbox responses, whose encapsulated size is pinned to
/// [`ENCAPSULATED_MESSAGE_BYTES`](crate::directory::ENCAPSULATED_MESSAGE_BYTES),
/// a queue page is validated by its decapsulated body size; the
/// encapsulated size is the directory's concern.
fn process_queue_response(
    res: &[u8],
    context: OhttpResponse,
) -> Result<(u64, Vec<u8>), StaticPollError> {
    let response = ohttp_decapsulate(context.into_inner(), res)
        .map_err(InternalStaticPollError::Decapsulation)?;
    if response.status() != http::StatusCode::OK {
        return Err(InternalStaticPollError::UnexpectedStatusCode(response.status()).into());
    }
    let next = response
        .headers()
        .get(QUEUE_NEXT_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or(InternalStaticPollError::MissingNextCursor)?;
    let body = response.into_body();
    if body.len() != QUEUE_PAGE_BYTES {
        return Err(InternalStaticPollError::UnexpectedPageSize(body.len()).into());
    }
    Ok((next, body))
}

/// Represents a piece of information the static receiver has obtained.
///
/// Unlike a standard session's events, these do not drive typestate
/// progression; they record queue consumption (which frames were handled,
/// where to poll next) so a replayed session neither re-processes a frame
/// nor re-fetches consumed pages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StaticSessionEvent {
    Created(StaticSessionContext),
    /// A frame that failed HPKE decryption: another client's frame or spam
    /// on the world-addressable queue. Non-fatal by design; see the module
    /// documentation.
    SkippedUndecryptable(FrameHash),
    /// A frame that decrypted with the session key but did not carry a
    /// well-formed Original PSBT payload.
    SkippedInvalidPayload(FrameHash),
    /// A frame that decrypted to a valid message A. Carries the payload so
    /// a proposal lost between persisting the poll and seeding its
    /// sub-session log can be recovered from the session history.
    RetrievedProposal {
        frame_hash: FrameHash,
        original: OriginalPayload,
        reply_key: HpkePublicKey,
    },
    /// The queue cursor to resume polling from.
    CursorAdvanced(u64),
    Closed,
}

/// A static receive session reconstructed from its event log: either still
/// live or deliberately closed.
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::large_enum_variant)]
pub enum StaticReceiveSession {
    Live(StaticReceiver),
    Closed,
}

fn replay_events(
    mut logs: impl Iterator<Item = StaticSessionEvent>,
) -> Result<
    (StaticReceiveSession, Vec<StaticSessionEvent>),
    ReplayError<StaticReceiveSession, StaticSessionEvent>,
> {
    let first_event = logs.next().ok_or(InternalReplayError::NoEvents)?;
    let mut session_events = vec![first_event.clone()];
    let mut receiver = match first_event {
        StaticSessionEvent::Created(context) =>
            StaticReceiver { context, cursor: 0, seen: HashSet::new() },
        _ => return Err(InternalReplayError::InvalidEvent(Box::new(first_event), None).into()),
    };

    for event in logs {
        session_events.push(event.clone());
        match event {
            StaticSessionEvent::SkippedUndecryptable(hash)
            | StaticSessionEvent::SkippedInvalidPayload(hash)
            | StaticSessionEvent::RetrievedProposal { frame_hash: hash, .. } => {
                receiver.seen.insert(hash);
            }
            StaticSessionEvent::CursorAdvanced(next) => receiver.cursor = next,
            StaticSessionEvent::Closed =>
                return Ok((StaticReceiveSession::Closed, session_events)),
            StaticSessionEvent::Created(_) =>
                return Err(InternalReplayError::InvalidEvent(
                    Box::new(event),
                    Some(Box::new(StaticReceiveSession::Live(receiver))),
                )
                .into()),
        }
    }
    Ok((StaticReceiveSession::Live(receiver), session_events))
}

/// Replay a static receiver event log to get the receiver in its current
/// state and a [`StaticSessionHistory`].
///
/// There is no expiration check, unlike the standard session replay: a
/// static session stays replayable for as long as its log exists.
pub fn replay_static_event_log<P>(
    persister: &P,
) -> Result<
    (StaticReceiveSession, StaticSessionHistory),
    ReplayError<StaticReceiveSession, StaticSessionEvent>,
>
where
    P: SessionPersister,
    P::SessionEvent: Into<StaticSessionEvent> + Clone,
    P::SessionEvent: From<StaticSessionEvent>,
{
    let logs = persister
        .load()
        .map_err(|e| InternalReplayError::PersistenceFailure(ImplementationError::new(e)))?;

    let (receiver, session_events) = match replay_events(logs.map(|e| e.into())) {
        Ok(r) => r,
        Err(e) => {
            persister.close().map_err(|ce| {
                InternalReplayError::PersistenceFailure(ImplementationError::new(ce))
            })?;
            return Err(e);
        }
    };

    Ok((receiver, StaticSessionHistory { events: session_events }))
}

/// Async version of [`replay_static_event_log`].
pub async fn replay_static_event_log_async<P>(
    persister: &P,
) -> Result<
    (StaticReceiveSession, StaticSessionHistory),
    ReplayError<StaticReceiveSession, StaticSessionEvent>,
>
where
    P: AsyncSessionPersister,
    P::SessionEvent: Into<StaticSessionEvent> + Clone,
    P::SessionEvent: From<StaticSessionEvent>,
{
    let logs = persister
        .load()
        .await
        .map_err(|e| InternalReplayError::PersistenceFailure(ImplementationError::new(e)))?;

    let (receiver, session_events) = match replay_events(logs.map(|e| e.into())) {
        Ok(r) => r,
        Err(e) => {
            persister.close().await.map_err(|ce| {
                InternalReplayError::PersistenceFailure(ImplementationError::new(ce))
            })?;
            return Err(e);
        }
    };

    Ok((receiver, StaticSessionHistory { events: session_events }))
}

/// The events that have occurred during a static receiver's session,
/// obtained from [`replay_static_event_log`].
#[derive(Debug, Clone)]
pub struct StaticSessionHistory {
    events: Vec<StaticSessionEvent>,
}

impl StaticSessionHistory {
    /// The static session's payjoin URI.
    pub fn pj_uri(&self) -> crate::PjUri {
        self.events
            .iter()
            .find_map(|event| match event {
                StaticSessionEvent::Created(context) => Some(pj_uri(context)),
                _ => None,
            })
            .expect("Session event log must begin with a Created event")
    }

    /// Every proposal this session has retrieved, in retrieval order.
    ///
    /// An application that crashed after persisting a poll but before
    /// seeding a proposal's sub-session log can recover the proposal here
    /// and seed it late. Seeding the same proposal twice is guarded by the
    /// sub-session's
    /// [`check_no_inputs_seen_before`](super::Receiver::check_no_inputs_seen_before)
    /// validation.
    pub fn proposals(&self) -> Vec<InboundProposal> {
        let context = self.events.iter().find_map(|event| match event {
            StaticSessionEvent::Created(context) => Some(context.clone()),
            _ => None,
        });
        let Some(context) = context else {
            return Vec::new();
        };
        self.events
            .iter()
            .filter_map(|event| match event {
                StaticSessionEvent::RetrievedProposal { original, reply_key, .. } =>
                    Some(InboundProposal {
                        context: context.clone(),
                        original: original.clone(),
                        reply_key: reply_key.clone(),
                    }),
                _ => None,
            })
            .collect()
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use payjoin_test_utils::{BoxError, EXAMPLE_URL, PARSED_ORIGINAL_PSBT};

    use super::*;
    use crate::hpke::encrypt_message_a;
    use crate::persist::InMemoryPersister;
    use crate::receive::v2::{replay_event_log, ReceiveSession};

    fn static_receiver_with(persister: &InMemoryPersister<StaticSessionEvent>) -> StaticReceiver {
        StaticReceiverBuilder::new(
            Address::from_str("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4")
                .expect("valid address")
                .assume_checked(),
            EXAMPLE_URL,
            OhttpKeys::decode(&payjoin_test_utils::ohttp_key_config_bytes())
                .expect("valid ohttp keys"),
            HpkeKeyPair::gen_keypair(),
        )
        .expect("valid directory URL")
        .build()
        .save(persister)
        .expect("in-memory persister should not fail")
    }

    fn message_a_frame(receiver_pk: &HpkePublicKey, reply_keypair: &HpkeKeyPair) -> Vec<u8> {
        let body = crate::send::v2::serialize_v2_body(
            &PARSED_ORIGINAL_PSBT,
            OutputSubstitution::Enabled,
            None,
            FeeRate::ZERO,
        )
        .expect("test payload should serialize");
        let frame = encrypt_message_a(body, reply_keypair.public_key(), receiver_pk)
            .expect("test payload should encrypt");
        assert_eq!(frame.len(), QUEUE_FRAME_BYTES);
        frame
    }

    fn garbage_frame() -> Vec<u8> { vec![0xAB; QUEUE_FRAME_BYTES] }

    fn queue_response(req_body: &[u8], frames: &[&[u8]], next: u64) -> Vec<u8> {
        queue_response_parts(req_body, frames, Some(next), http::StatusCode::OK)
    }

    fn queue_response_parts(
        req_body: &[u8],
        frames: &[&[u8]],
        next: Option<u64>,
        status: http::StatusCode,
    ) -> Vec<u8> {
        let server = payjoin_test_utils::ohttp_server();
        let (_, server_response) =
            server.decapsulate(req_body).expect("request should decapsulate");
        let mut page = vec![0u8; QUEUE_PAGE_BYTES];
        for (i, frame) in frames.iter().enumerate() {
            assert_eq!(frame.len(), QUEUE_FRAME_BYTES);
            page[i * QUEUE_FRAME_BYTES..(i + 1) * QUEUE_FRAME_BYTES].copy_from_slice(frame);
        }
        let mut message = bhttp::Message::response(
            bhttp::StatusCode::try_from(status.as_u16()).expect("status should be valid"),
        );
        if let Some(next) = next {
            message.put_header(QUEUE_NEXT_HEADER, next.to_string());
        }
        message.write_content(&page);
        let mut buf = Vec::new();
        message.write_bhttp(bhttp::Mode::KnownLength, &mut buf).expect("BHTTP should encode");
        server_response.encapsulate(&buf).expect("response should encrypt")
    }

    #[test]
    fn poll_request_targets_queue_with_cursor() -> Result<(), BoxError> {
        let persister = InMemoryPersister::default();
        let receiver = static_receiver_with(&persister);
        let (req, _ctx) = receiver.create_poll_request(EXAMPLE_URL)?;
        assert_eq!(req.body.len(), crate::directory::ENCAPSULATED_MESSAGE_BYTES);

        let server = payjoin_test_utils::ohttp_server();
        let (bhttp_bytes, _) = server.decapsulate(&req.body)?;
        let message = bhttp::Message::read_bhttp(&mut std::io::Cursor::new(bhttp_bytes))?;
        assert_eq!(message.control().method(), Some(&b"GET"[..]));
        let expected_path = format!("/q/{}?after=0", receiver.context.queue_id());
        assert_eq!(message.control().path(), Some(expected_path.as_bytes()));
        Ok(())
    }

    #[test]
    fn garbage_and_valid_frames_yield_proposal_and_session_stays_open() -> Result<(), BoxError> {
        let persister = InMemoryPersister::default();
        let receiver = static_receiver_with(&persister);
        let reply_keypair = HpkeKeyPair::gen_keypair();
        let valid = message_a_frame(receiver.context.receiver_key.public_key(), &reply_keypair);
        let garbage = garbage_frame();

        let (req, ctx) = receiver.create_poll_request(EXAMPLE_URL)?;
        let response = queue_response(&req.body, &[&garbage, &valid], 2);
        let (receiver, proposals) = receiver.process_response(&response, ctx).save(&persister)?;

        assert_eq!(proposals.len(), 1);
        assert_eq!(receiver.cursor, 2);
        let inner = persister.inner.lock().expect("lock should not be poisoned");
        assert!(!inner.is_closed, "an undecryptable frame must not close a static session");
        assert!(matches!(inner.events[1], StaticSessionEvent::SkippedUndecryptable(_)));
        assert!(matches!(inner.events[2], StaticSessionEvent::RetrievedProposal { .. }));
        assert!(matches!(inner.events[3], StaticSessionEvent::CursorAdvanced(2)));
        Ok(())
    }

    #[test]
    fn garbage_only_poll_is_not_fatal_and_session_persists() -> Result<(), BoxError> {
        let persister = InMemoryPersister::default();
        let receiver = static_receiver_with(&persister);
        let garbage = garbage_frame();

        let (req, ctx) = receiver.create_poll_request(EXAMPLE_URL)?;
        let response = queue_response(&req.body, &[&garbage], 1);
        let (live, proposals) = receiver.process_response(&response, ctx).save(&persister)?;

        assert!(proposals.is_empty());
        assert!(!persister.inner.lock().expect("lock should not be poisoned").is_closed);

        let (replayed, _) = replay_static_event_log(&persister)?;
        assert_eq!(replayed, StaticReceiveSession::Live(live));
        Ok(())
    }

    #[test]
    fn duplicate_ciphertext_across_polls_is_processed_once() -> Result<(), BoxError> {
        let persister = InMemoryPersister::default();
        let receiver = static_receiver_with(&persister);
        let reply_keypair = HpkeKeyPair::gen_keypair();
        let valid = message_a_frame(receiver.context.receiver_key.public_key(), &reply_keypair);

        let (req, ctx) = receiver.create_poll_request(EXAMPLE_URL)?;
        let response = queue_response(&req.body, &[&valid], 1);
        let (receiver, proposals) = receiver.process_response(&response, ctx).save(&persister)?;
        assert_eq!(proposals.len(), 1);

        // The directory redelivers the same frame in the next page.
        let (req, ctx) = receiver.create_poll_request(EXAMPLE_URL)?;
        let response = queue_response(&req.body, &[&valid], 1);
        let (receiver, proposals) = receiver.process_response(&response, ctx).save(&persister)?;
        assert!(proposals.is_empty(), "a redelivered frame must not yield a second proposal");

        // Dedupe state survives replay.
        let (replayed, history) = replay_static_event_log(&persister)?;
        assert_eq!(replayed, StaticReceiveSession::Live(receiver));
        assert_eq!(history.proposals().len(), 1);
        Ok(())
    }

    #[test]
    fn page_handles_zero_to_four_frames_with_zero_padding() -> Result<(), BoxError> {
        let persister = InMemoryPersister::default();
        let receiver = static_receiver_with(&persister);

        // An all-zero page is only padding: nothing persists, cursor stays.
        let (req, ctx) = receiver.create_poll_request(EXAMPLE_URL)?;
        let response = queue_response(&req.body, &[], 0);
        let (receiver, proposals) = receiver.process_response(&response, ctx).save(&persister)?;
        assert!(proposals.is_empty());
        assert_eq!(receiver.cursor, 0);
        assert_eq!(persister.inner.lock().expect("lock should not be poisoned").events.len(), 1);

        // A full page of distinct message A frames yields one proposal each.
        let reply_keypair = HpkeKeyPair::gen_keypair();
        let receiver_pk = receiver.context.receiver_key.public_key().clone();
        let frames: Vec<Vec<u8>> =
            (0..4).map(|_| message_a_frame(&receiver_pk, &reply_keypair)).collect();
        let frame_refs: Vec<&[u8]> = frames.iter().map(|f| f.as_slice()).collect();
        let (req, ctx) = receiver.create_poll_request(EXAMPLE_URL)?;
        let response = queue_response(&req.body, &frame_refs, 4);
        let (receiver, proposals) = receiver.process_response(&response, ctx).save(&persister)?;
        assert_eq!(proposals.len(), 4);
        assert_eq!(receiver.cursor, 4);
        Ok(())
    }

    #[test]
    fn non_ok_queue_response_is_transient() -> Result<(), BoxError> {
        let persister = InMemoryPersister::default();
        let receiver = static_receiver_with(&persister);

        let (req, ctx) = receiver.create_poll_request(EXAMPLE_URL)?;
        let response =
            queue_response_parts(&req.body, &[], Some(0), http::StatusCode::INTERNAL_SERVER_ERROR);
        let err = receiver
            .process_response(&response, ctx)
            .save(&persister)
            .expect_err("a non-OK response should be a transient error");

        assert!(err.is_transient());
        let receiver = err.transient_state().expect("session should be returned for retry");
        assert_eq!(receiver.cursor, 0);
        assert_eq!(persister.inner.lock().expect("lock should not be poisoned").events.len(), 1);
        Ok(())
    }

    #[test]
    fn missing_next_cursor_is_transient() -> Result<(), BoxError> {
        let persister = InMemoryPersister::default();
        let receiver = static_receiver_with(&persister);

        let (req, ctx) = receiver.create_poll_request(EXAMPLE_URL)?;
        let response = queue_response_parts(&req.body, &[], None, http::StatusCode::OK);
        let err = receiver
            .process_response(&response, ctx)
            .save(&persister)
            .expect_err("a response without a cursor should be a transient error");
        assert!(err.is_transient());
        Ok(())
    }

    #[test]
    fn inbound_proposal_seeds_standard_sub_session() -> Result<(), BoxError> {
        let persister = InMemoryPersister::default();
        let receiver = static_receiver_with(&persister);
        let reply_keypair = HpkeKeyPair::gen_keypair();
        let valid = message_a_frame(receiver.context.receiver_key.public_key(), &reply_keypair);

        let (req, ctx) = receiver.create_poll_request(EXAMPLE_URL)?;
        let response = queue_response(&req.body, &[&valid], 1);
        let (_receiver, mut proposals) =
            receiver.process_response(&response, ctx).save(&persister)?;
        let proposal = proposals.pop().expect("one proposal should be yielded");

        let sub_persister = InMemoryPersister::<SessionEvent>::default();
        let unchecked = proposal.save(&sub_persister)?;

        // The sender's fresh reply key is threaded through so the reply
        // reaches the sender's mailbox.
        assert_eq!(unchecked.session_context.reply_key.as_ref(), Some(reply_keypair.public_key()));

        // The seeded log replays like any standard session.
        let (replayed, _) = replay_event_log(&sub_persister)?;
        assert_eq!(replayed, ReceiveSession::UncheckedOriginalPayload(unchecked.clone()));

        // Redelivered duplicates that slip past ciphertext dedupe (e.g. a
        // re-encrypted copy of the same original) die at the standard
        // input-seen check.
        let maybe_inputs_owned = unchecked.assume_interactive_receiver().save(&sub_persister)?;
        let maybe_inputs_seen =
            maybe_inputs_owned.check_inputs_not_owned(&mut |_| Ok(false)).save(&sub_persister)?;
        let err = maybe_inputs_seen
            .check_no_inputs_seen_before(&mut |_| Ok(true))
            .save(&sub_persister)
            .expect_err("inputs seen before must be rejected");
        assert!(err.is_fatal());
        Ok(())
    }

    #[test]
    fn pj_uri_round_trips_as_static() -> Result<(), BoxError> {
        let persister = InMemoryPersister::default();
        let receiver = static_receiver_with(&persister);
        let uri = receiver.pj_uri().to_string();
        let parsed = crate::Uri::try_from(uri.as_str())?
            .assume_checked()
            .check_pj_supported()
            .expect("static pj URI should support payjoin");
        match parsed.extras().pj_param() {
            crate::uri::PjParam::V2Static(param) =>
                assert_eq!(param.receiver_pubkey(), receiver.context.receiver_key.public_key()),
            other => panic!("expected a static pj param, got {other:?}"),
        }
        Ok(())
    }

    #[test]
    fn closed_session_replays_closed() -> Result<(), BoxError> {
        let persister = InMemoryPersister::default();
        let receiver = static_receiver_with(&persister);
        receiver.close().save(&persister)?;
        assert!(persister.inner.lock().expect("lock should not be poisoned").is_closed);
        let (replayed, _) = replay_static_event_log(&persister)?;
        assert_eq!(replayed, StaticReceiveSession::Closed);
        Ok(())
    }

    #[test]
    fn static_session_event_serialization_roundtrip() -> Result<(), BoxError> {
        let persister = InMemoryPersister::default();
        let receiver = static_receiver_with(&persister);
        let reply_keypair = HpkeKeyPair::gen_keypair();
        let frame = message_a_frame(receiver.context.receiver_key.public_key(), &reply_keypair);
        let frame_hash = FrameHash::from_frame(&frame);
        let (payload, reply_key) =
            decrypt_message_a(&frame, receiver.context.receiver_key.secret_key())?;
        let original = original_payload_from_str(std::str::from_utf8(&payload)?)
            .expect("test frame payload should parse");

        let test_cases = vec![
            StaticSessionEvent::Created(receiver.context.clone()),
            StaticSessionEvent::SkippedUndecryptable(frame_hash),
            StaticSessionEvent::SkippedInvalidPayload(frame_hash),
            StaticSessionEvent::RetrievedProposal { frame_hash, original, reply_key },
            StaticSessionEvent::CursorAdvanced(42),
            StaticSessionEvent::Closed,
        ];
        for event in test_cases {
            let serialized = serde_json::to_string(&event)?;
            let deserialized: StaticSessionEvent = serde_json::from_str(&serialized)?;
            assert_eq!(event, deserialized);
        }
        Ok(())
    }
}
