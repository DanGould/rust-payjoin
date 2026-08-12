//! Send a Payjoin to a static session: a long-lived, multi-sender payment
//! endpoint.
//!
//! The flow mirrors the standard v2 sender with two differences:
//!
//! - Message A is posted as a single frame to the receiver's queue
//!   (`/q/{id}`) rather than to a per-session mailbox, because the
//!   receiver's endpoint is shared by many concurrent senders.
//! - The payjoin URI carries no expiration, so the deadline for the
//!   payjoin to complete is this sender's per-payment policy — its
//!   *patience* — rather than a property of the receiver's URI. When the
//!   patience elapses, request construction fails with an expiration error
//!   and [`StaticSender::cancel`] yields the fallback transaction to
//!   broadcast, completing the payment without payjoin.
//!
//! The reply path is unchanged from the standard v2 sender: replies arrive
//! in the mailbox derived from this sender's fresh reply key, which only
//! this sender and the receiver can address, so an undecryptable reply
//! remains an integrity failure there even though the receiver's own queue
//! tolerates undecryptable frames.

#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use bitcoin::psbt::Psbt;
use bitcoin::{Address, Amount, FeeRate};
use serde::{Deserialize, Serialize};
#[cfg(target_arch = "wasm32")]
use web_time::Duration;

use super::error::{InternalCreateRequestError, InternalDecapsulationError};
use super::{
    CreateRequestError, DecapsulationError, PendingFallback, PollingForProposal, SessionOutcome,
    SessionStatus, State, WithReplyKey,
};
use crate::core::Url;
use crate::error::{InternalReplayError, ReplayError};
use crate::hpke::{encrypt_message_a, HpkeKeyPair, HpkeSecretKey};
use crate::ohttp::{ohttp_encapsulate, process_get_res, process_post_res, OhttpResponse};
use crate::output_substitution::OutputSubstitution;
use crate::persist::{
    AsyncSessionPersister, MaybeFatalTransition, MaybeSuccessTransitionWithNoResults,
    NextStateTransition, SessionPersister, TerminalTransition,
};
use crate::send::error::{BuildSenderError, ResponseError};
use crate::send::{clear_unneeded_fields, InternalProposalError, PsbtContext, PsbtContextBuilder};
use crate::time::Time;
use crate::uri::v2::StaticPjParam;
use crate::{ImplementationError, IntoUrl, PjUri, Request};

/// A builder to construct the properties of a [`StaticSender`].
///
/// Like the standard v2 [`SenderBuilder`](super::SenderBuilder), the
/// receiver's output substitution preference cannot be disabled by a third
/// party: all communications are end-to-end authenticated, so only the
/// receiver can substitute outputs.
#[derive(Clone)]
pub struct StaticSenderBuilder {
    pj_param: StaticPjParam,
    output_substitution: OutputSubstitution,
    psbt_ctx_builder: PsbtContextBuilder,
    patience: Option<Duration>,
}

impl StaticSenderBuilder {
    /// Prepare the context from which to make sender requests.
    ///
    /// Call [`StaticSenderBuilder::build_recommended`] or other `build`
    /// methods to create a [`StaticSender`].
    pub fn new(psbt: Psbt, uri: PjUri) -> Self {
        match uri.extras().pj_param() {
            crate::uri::PjParam::V2Static(pj_param) =>
                Self::from_parts(psbt, pj_param, uri.address(), uri.amount()),
            _ => unimplemented!("StaticSenderBuilder only supports static session URLs"),
        }
    }

    pub fn from_parts(
        psbt: Psbt,
        pj_param: &StaticPjParam,
        address: &Address,
        amount: Option<Amount>,
    ) -> Self {
        Self {
            pj_param: pj_param.clone(),
            // Ignore the receiver's output substitution preference, because all
            // communications with the receiver are end-to-end authenticated. So a
            // malicious man in the middle can't substitute outputs, only the receiver can.
            output_substitution: OutputSubstitution::Enabled,
            psbt_ctx_builder: PsbtContextBuilder::new(psbt, address.script_pubkey(), amount),
            patience: None,
        }
    }

    /// Disable output substitution even if the receiver didn't.
    ///
    /// This forbids receiver switching output or decreasing amount.
    /// It is generally **not** recommended to set this as it may prevent the receiver from
    /// doing advanced operations such as opening LN channels and it also guarantees the
    /// receiver will **not** reward the sender with a discount.
    pub fn always_disable_output_substitution(self) -> Self {
        Self { output_substitution: OutputSubstitution::Disabled, ..self }
    }

    /// Give up on the payjoin after `patience` and fall back to broadcasting
    /// the original transaction.
    ///
    /// A static session URI carries no expiration, so how long to wait for
    /// the receiver is decided here, per payment. Once the patience
    /// elapses, request construction fails with an expiration error and
    /// [`StaticSender::cancel`] yields the fallback transaction. Without a
    /// patience the sender polls until cancelled.
    pub fn with_patience(self, patience: Duration) -> Self {
        Self { patience: Some(patience), ..self }
    }

    // Calculate the recommended fee contribution for an Original PSBT.
    //
    // BIP 78 recommends contributing `originalPSBTFeeRate * vsize(sender_input_type)`.
    // The minfeerate parameter is set if the contribution is available in change.
    //
    // This method fails if no recommendation can be made or if the PSBT is malformed.
    pub fn build_recommended(
        self,
        min_fee_rate: FeeRate,
    ) -> Result<NextStateTransition<StaticSessionEvent, StaticSender<WithReplyKey>>, BuildSenderError>
    {
        let psbt_ctx =
            self.psbt_ctx_builder.build_recommended(min_fee_rate, self.output_substitution)?;
        Ok(Self::transition_from_psbt_ctx(self.pj_param, psbt_ctx, self.patience))
    }

    /// Offer the receiver contribution to pay for his input.
    ///
    /// These parameters will allow the receiver to take `max_fee_contribution` from given change
    /// output to pay for additional inputs. The recommended fee is `size_of_one_input * fee_rate`.
    ///
    /// `change_index` specifies which output can be used to pay fee. If `None` is provided, then
    /// the output is auto-detected unless the supplied transaction has more than two outputs.
    ///
    /// `clamp_fee_contribution` decreases fee contribution instead of erroring.
    ///
    /// If this option is true and a transaction with change amount lower than fee
    /// contribution is provided then instead of returning error the fee contribution will
    /// be just lowered in the request to match the change amount.
    pub fn build_with_additional_fee(
        self,
        max_fee_contribution: bitcoin::Amount,
        change_index: Option<usize>,
        min_fee_rate: FeeRate,
        clamp_fee_contribution: bool,
    ) -> Result<NextStateTransition<StaticSessionEvent, StaticSender<WithReplyKey>>, BuildSenderError>
    {
        let psbt_ctx = self.psbt_ctx_builder.build_with_additional_fee(
            max_fee_contribution,
            change_index,
            min_fee_rate,
            clamp_fee_contribution,
            self.output_substitution,
        )?;
        Ok(Self::transition_from_psbt_ctx(self.pj_param, psbt_ctx, self.patience))
    }

    /// Perform Payjoin without incentivizing the payee to cooperate.
    ///
    /// While it's generally better to offer some contribution some users may wish not to.
    /// This function disables contribution.
    pub fn build_non_incentivizing(
        self,
        min_fee_rate: FeeRate,
    ) -> Result<NextStateTransition<StaticSessionEvent, StaticSender<WithReplyKey>>, BuildSenderError>
    {
        let psbt_ctx = self
            .psbt_ctx_builder
            .build_non_incentivizing(min_fee_rate, self.output_substitution)?;
        Ok(Self::transition_from_psbt_ctx(self.pj_param, psbt_ctx, self.patience))
    }

    fn transition_from_psbt_ctx(
        pj_param: StaticPjParam,
        psbt_ctx: PsbtContext,
        patience: Option<Duration>,
    ) -> NextStateTransition<StaticSessionEvent, StaticSender<WithReplyKey>> {
        let patience = patience.map(|patience| {
            Time::from_now(patience).expect("specifying patience as Duration should not fail")
        });
        let sender = StaticSender {
            state: WithReplyKey,
            session_context: StaticSessionContext {
                pj_param,
                psbt_ctx,
                reply_key: HpkeKeyPair::gen_keypair().0,
                patience,
            },
        };
        NextStateTransition::success(
            StaticSessionEvent::Created(Box::new(sender.session_context.clone())),
            sender,
        )
    }
}

/// Data required for a static session sender throughout its lifetime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticSessionContext {
    /// The static endpoint in the Payjoin URI
    pub(crate) pj_param: StaticPjParam,
    /// The Original PSBT context
    pub(crate) psbt_ctx: PsbtContext,
    /// The secret key to decrypt the receiver's reply.
    pub(crate) reply_key: HpkeSecretKey,
    /// This sender's own deadline for the payjoin to complete. `None`
    /// polls until cancelled.
    pub(crate) patience: Option<Time>,
}

impl StaticSessionContext {
    fn full_relay_url(&self, ohttp_relay: impl IntoUrl) -> Result<Url, InternalCreateRequestError> {
        let relay_base = ohttp_relay.into_url().map_err(InternalCreateRequestError::Url)?;

        // Only reveal scheme and authority to the relay
        let directory_base = self
            .pj_param
            .endpoint()
            .join("/")
            .map_err(|e| InternalCreateRequestError::Url(e.into()))?;

        // Append that information as a path to the relay URL
        relay_base
            .join(&format!("/{directory_base}"))
            .map_err(|e| InternalCreateRequestError::Url(e.into()))
    }

    /// Fail with an expiration error once this sender's patience has
    /// elapsed, prompting fallback broadcast via [`StaticSender::cancel`].
    fn check_patience(&self) -> Result<(), InternalCreateRequestError> {
        if let Some(patience) = self.patience {
            if patience.elapsed() {
                return Err(InternalCreateRequestError::Expired(patience));
            }
        }
        Ok(())
    }
}

/// A static session Payjoin sender, allowing the construction of requests
/// against a long-lived, multi-sender receiver endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StaticSender<State> {
    pub(crate) state: State,
    pub(crate) session_context: StaticSessionContext,
}

impl<State> core::ops::Deref for StaticSender<State> {
    type Target = State;

    fn deref(&self) -> &Self::Target { &self.state }
}

impl<State> core::ops::DerefMut for StaticSender<State> {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.state }
}

impl<S: State> StaticSender<S> {
    /// Cancel the Payjoin session and once the transition is persisted, return a
    /// [`PendingFallback`] state. The fallback transaction is the sender's original
    /// transaction that should be broadcast to complete the payment without Payjoin.
    pub fn cancel(self) -> NextStateTransition<StaticSessionEvent, StaticSender<PendingFallback>> {
        NextStateTransition::success(
            StaticSessionEvent::Cancelled(),
            StaticSender {
                state: PendingFallback {
                    fallback_tx: self
                        .session_context
                        .psbt_ctx
                        .original_psbt
                        .clone()
                        .extract_tx_unchecked_fee_rate(),
                },
                session_context: self.session_context,
            },
        )
    }
}

impl StaticSender<WithReplyKey> {
    /// Construct an OHTTP encapsulated request posting message A as a
    /// single frame to the receiver's queue.
    ///
    /// Important: This request must not be retried or reused on failure.
    /// Retransmitting the same ciphertext breaks OHTTP privacy properties.
    pub fn create_v2_post_request(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, OhttpResponse), CreateRequestError> {
        self.session_context.check_patience()?;

        let mut sanitized_psbt = self.session_context.psbt_ctx.original_psbt.clone();
        clear_unneeded_fields(&mut sanitized_psbt);
        let body = super::serialize_v2_body(
            &sanitized_psbt,
            self.session_context.psbt_ctx.output_substitution,
            self.session_context.psbt_ctx.fee_contribution,
            self.session_context.psbt_ctx.min_fee_rate,
        )?;
        let body = encrypt_message_a(
            body,
            HpkeKeyPair::from_secret_key(&self.session_context.reply_key).public_key(),
            self.session_context.pj_param.receiver_pubkey(),
        )
        .map_err(InternalCreateRequestError::Hpke)?;

        let target = self.session_context.pj_param.queue_endpoint();
        let (body, ohttp_ctx) = ohttp_encapsulate(
            self.session_context.pj_param.ohttp_keys(),
            "POST",
            target.as_str(),
            Some(&body),
        )
        .map_err(InternalCreateRequestError::OhttpEncapsulation)?;
        let request = Request::new_v2(&self.session_context.full_relay_url(ohttp_relay)?, &body);
        Ok((request, OhttpResponse::new(ohttp_ctx)))
    }

    /// Processes the response for the initial POST message from the sender
    /// client in the v2 Payjoin protocol.
    ///
    /// This function decapsulates the response using the provided OHTTP
    /// context. If the encapsulated response status is successful, it
    /// indicates that the Original PSBT was accepted into the queue.
    /// Otherwise, it returns an error with the encapsulated status code.
    ///
    /// After this function is called, the sender can poll for a Proposal PSBT
    /// from the receiver using the returned [`PollingForProposal`] state.
    pub fn process_response(
        self,
        response: &[u8],
        post_ctx: OhttpResponse,
    ) -> MaybeFatalTransition<
        StaticSessionEvent,
        StaticSender<PollingForProposal>,
        DecapsulationError,
        (),
        Self,
    > {
        match process_post_res(response, post_ctx.into_inner()) {
            Ok(()) => {}
            Err(e) =>
                if e.is_fatal() {
                    return MaybeFatalTransition::fatal(
                        StaticSessionEvent::Closed(SessionOutcome::Aborted),
                        InternalDecapsulationError::DirectoryResponse(e).into(),
                    );
                } else {
                    return MaybeFatalTransition::transient(
                        InternalDecapsulationError::DirectoryResponse(e).into(),
                        self,
                    );
                },
        }

        let sender =
            StaticSender { state: PollingForProposal, session_context: self.session_context };
        MaybeFatalTransition::success(StaticSessionEvent::PostedOriginalPsbt(), sender)
    }

    pub(crate) fn apply_polling_for_proposal(self) -> StaticSendSession {
        StaticSendSession::PollingForProposal(StaticSender {
            state: PollingForProposal,
            session_context: self.session_context,
        })
    }
}

impl StaticSender<PollingForProposal> {
    /// Construct an OHTTP encapsulated GET request for the Proposal PSBT.
    ///
    /// The reply mailbox is derived from this sender's fresh reply key
    /// exactly as in a standard v2 session; only message A's delivery
    /// differs in a static session.
    pub fn create_poll_request(
        &self,
        ohttp_relay: impl IntoUrl,
    ) -> Result<(Request, OhttpResponse), CreateRequestError> {
        self.session_context.check_patience()?;

        let mailbox = crate::uri::ShortId::from(
            HpkeKeyPair::from_secret_key(&self.session_context.reply_key).public_key(),
        );
        let url = self
            .session_context
            .pj_param
            .endpoint()
            .join(&mailbox.to_string())
            .map_err(|e| InternalCreateRequestError::Url(e.into()))?;
        let body = encrypt_message_a(
            Vec::new(),
            HpkeKeyPair::from_secret_key(&self.session_context.reply_key).public_key(),
            self.session_context.pj_param.receiver_pubkey(),
        )
        .map_err(InternalCreateRequestError::Hpke)?;
        let ohttp_keys = self.session_context.pj_param.ohttp_keys();
        let (body, ohttp_ctx) = ohttp_encapsulate(ohttp_keys, "GET", url.as_str(), Some(&body))
            .map_err(InternalCreateRequestError::OhttpEncapsulation)?;

        Ok((
            Request::new_v2(&self.session_context.full_relay_url(ohttp_relay)?, &body),
            OhttpResponse::new(ohttp_ctx),
        ))
    }

    /// Processes the response for the final GET message from the sender client
    /// in the v2 Payjoin protocol.
    ///
    /// A successful response can either be a Proposal PSBT or an ACCEPTED
    /// message indicating no Proposal PSBT is available yet. An
    /// undecryptable reply remains fatal here even though the receiver's
    /// queue tolerates undecryptable frames: this sender's reply mailbox is
    /// derived from its fresh, unshared reply key, so garbage there is an
    /// integrity failure, not another client's traffic.
    ///
    /// After this function is called, the sender can sign and finalize the
    /// PSBT and broadcast the resulting Payjoin transaction to the network.
    pub fn process_response(
        self,
        response: &[u8],
        ohttp_ctx: OhttpResponse,
    ) -> MaybeSuccessTransitionWithNoResults<
        StaticSessionEvent,
        Psbt,
        StaticSender<PollingForProposal>,
        ResponseError,
    > {
        let body = match process_get_res(response, ohttp_ctx.into_inner()) {
            Ok(Some(body)) => body,
            Ok(None) => return MaybeSuccessTransitionWithNoResults::no_results(self),
            Err(e) =>
                if e.is_fatal() {
                    return MaybeSuccessTransitionWithNoResults::fatal(
                        StaticSessionEvent::Closed(SessionOutcome::Aborted),
                        InternalDecapsulationError::DirectoryResponse(e).into(),
                    );
                } else {
                    return MaybeSuccessTransitionWithNoResults::transient(
                        InternalDecapsulationError::DirectoryResponse(e).into(),
                        self,
                    );
                },
        };

        let body = match crate::hpke::decrypt_message_b(
            &body,
            self.session_context.pj_param.receiver_pubkey().clone(),
            &self.session_context.reply_key,
        ) {
            Ok(body) => body,
            Err(e) =>
                return MaybeSuccessTransitionWithNoResults::fatal(
                    StaticSessionEvent::Closed(SessionOutcome::Aborted),
                    InternalDecapsulationError::Hpke(e).into(),
                ),
        };

        if let Ok(resp_err) = ResponseError::from_slice(&body) {
            return MaybeSuccessTransitionWithNoResults::fatal(
                StaticSessionEvent::Closed(SessionOutcome::Aborted),
                resp_err,
            );
        }

        let proposal = match Psbt::deserialize(&body) {
            Ok(proposal) => proposal,
            Err(e) =>
                return MaybeSuccessTransitionWithNoResults::fatal(
                    StaticSessionEvent::Closed(SessionOutcome::Aborted),
                    InternalProposalError::Psbt(e).into(),
                ),
        };
        let processed_proposal =
            match self.session_context.psbt_ctx.clone().process_proposal(proposal) {
                Ok(processed_proposal) => processed_proposal,
                Err(e) =>
                    return MaybeSuccessTransitionWithNoResults::fatal(
                        StaticSessionEvent::Closed(SessionOutcome::Aborted),
                        e.into(),
                    ),
            };

        MaybeSuccessTransitionWithNoResults::success(
            processed_proposal.clone(),
            StaticSessionEvent::Closed(SessionOutcome::Success(processed_proposal)),
        )
    }
}

impl StaticSender<PendingFallback> {
    /// Returns the fallback transaction that should be broadcast to complete the payment without Payjoin.
    pub fn fallback_tx(&self) -> &bitcoin::Transaction { &self.fallback_tx }

    /// Mark the session as complete, signaling that the fallback transaction
    /// has been broadcast or its control has been transferred.
    pub fn close(&self) -> TerminalTransition<StaticSessionEvent, ()> {
        TerminalTransition::new(StaticSessionEvent::Closed(SessionOutcome::Aborted), ())
    }
}

/// Represents the various states of a static session send session during
/// the protocol flow.
///
/// This provides type erasure for the send session state, allowing the session to be replayed
/// and the state to be updated with the next event over a uniform interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaticSendSession {
    WithReplyKey(StaticSender<WithReplyKey>),
    PollingForProposal(StaticSender<PollingForProposal>),
    PendingFallback(StaticSender<PendingFallback>),
    Closed(SessionOutcome),
}

impl StaticSendSession {
    fn new(session_context: StaticSessionContext) -> Self {
        StaticSendSession::WithReplyKey(StaticSender { state: WithReplyKey, session_context })
    }

    fn process_event(
        self,
        event: StaticSessionEvent,
    ) -> Result<StaticSendSession, ReplayError<Self, StaticSessionEvent>> {
        match (self, event) {
            (StaticSendSession::WithReplyKey(state), StaticSessionEvent::PostedOriginalPsbt()) =>
                Ok(state.apply_polling_for_proposal()),
            (StaticSendSession::WithReplyKey(state), StaticSessionEvent::Cancelled()) =>
                Ok(pending_fallback_from(state.session_context)),
            (StaticSendSession::PollingForProposal(state), StaticSessionEvent::Cancelled()) =>
                Ok(pending_fallback_from(state.session_context)),
            (_, StaticSessionEvent::Closed(session_outcome)) =>
                Ok(StaticSendSession::Closed(session_outcome)),
            (current_state, event) => Err(InternalReplayError::InvalidEvent(
                Box::new(event),
                Some(Box::new(current_state)),
            )
            .into()),
        }
    }
}

fn pending_fallback_from(session_context: StaticSessionContext) -> StaticSendSession {
    StaticSendSession::PendingFallback(StaticSender {
        state: PendingFallback {
            fallback_tx: session_context
                .psbt_ctx
                .original_psbt
                .clone()
                .extract_tx_unchecked_fee_rate(),
        },
        session_context,
    })
}

/// Represents a piece of information that the static session sender has
/// obtained from the session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StaticSessionEvent {
    /// Sender was created with session data
    Created(Box<StaticSessionContext>),
    /// Sender posted the Original PSBT to the receiver's queue and is
    /// waiting to receive a Proposal PSBT
    PostedOriginalPsbt(),
    /// User initiated cancellation of the session, e.g. after its patience
    /// elapsed
    Cancelled(),
    /// Closed successful or failed session
    Closed(SessionOutcome),
}

fn replay_events(
    mut logs: impl Iterator<Item = StaticSessionEvent>,
) -> Result<
    (StaticSendSession, Vec<StaticSessionEvent>),
    ReplayError<StaticSendSession, StaticSessionEvent>,
> {
    let first_event = logs.next().ok_or(InternalReplayError::NoEvents)?;
    let mut session_events = vec![first_event.clone()];
    let mut sender = match first_event {
        StaticSessionEvent::Created(session_context) => StaticSendSession::new(*session_context),
        _ => return Err(InternalReplayError::InvalidEvent(Box::new(first_event), None).into()),
    };

    for session_event in logs {
        session_events.push(session_event.clone());
        sender = sender.process_event(session_event)?;
    }
    Ok((sender, session_events))
}

/// Replay a static session sender event log to get the sender in its
/// current state [`StaticSendSession`] and a [`StaticSessionHistory`].
///
/// Unlike the standard sender replay, an elapsed patience is not an error:
/// patience is this sender's own policy, and the session stays replayable
/// so the caller can [`cancel`](StaticSender::cancel) into fallback
/// broadcast. Check [`StaticSessionHistory::status`] for expiration.
pub fn replay_static_event_log<P>(
    persister: &P,
) -> Result<
    (StaticSendSession, StaticSessionHistory),
    ReplayError<StaticSendSession, StaticSessionEvent>,
>
where
    P: SessionPersister,
    P::SessionEvent: Into<StaticSessionEvent> + Clone,
    P::SessionEvent: From<StaticSessionEvent>,
{
    let logs = persister
        .load()
        .map_err(|e| InternalReplayError::PersistenceFailure(ImplementationError::new(e)))?;

    let (sender, session_events) = match replay_events(logs.map(|e| e.into())) {
        Ok(r) => r,
        Err(e) => {
            persister.close().map_err(|ce| {
                InternalReplayError::PersistenceFailure(ImplementationError::new(ce))
            })?;
            return Err(e);
        }
    };

    Ok((sender, StaticSessionHistory { events: session_events }))
}

/// Async version of [`replay_static_event_log`].
pub async fn replay_static_event_log_async<P>(
    persister: &P,
) -> Result<
    (StaticSendSession, StaticSessionHistory),
    ReplayError<StaticSendSession, StaticSessionEvent>,
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

    let (sender, session_events) = match replay_events(logs.map(|e| e.into())) {
        Ok(r) => r,
        Err(e) => {
            persister.close().await.map_err(|ce| {
                InternalReplayError::PersistenceFailure(ImplementationError::new(ce))
            })?;
            return Err(e);
        }
    };

    Ok((sender, StaticSessionHistory { events: session_events }))
}

/// The events that have occurred during a static session sender's
/// lifetime, obtained from [`replay_static_event_log`].
#[derive(Debug, Clone)]
pub struct StaticSessionHistory {
    events: Vec<StaticSessionEvent>,
}

impl StaticSessionHistory {
    /// Fallback transaction from the session.
    pub fn fallback_tx(&self) -> bitcoin::Transaction {
        self.events
            .iter()
            .find_map(|event| match event {
                StaticSessionEvent::Created(session_context) => Some(
                    session_context.psbt_ctx.original_psbt.clone().extract_tx_unchecked_fee_rate(),
                ),
                _ => None,
            })
            .expect("Session event log must contain at least one event with fallback_tx")
    }

    pub fn pj_param(&self) -> &StaticPjParam {
        self.events
            .iter()
            .find_map(|event| match event {
                StaticSessionEvent::Created(session_context) => Some(&session_context.pj_param),
                _ => None,
            })
            .expect("Session event log must contain at least one event with pj_param")
    }

    /// Helper method to query the current status of the session.
    ///
    /// [`SessionStatus::Expired`] means this sender's own patience has
    /// elapsed; the receiver's endpoint itself does not expire.
    pub fn status(&self) -> SessionStatus {
        // Terminal states take precedence over expiration: a session that has reached
        // a `Closed` outcome is done regardless of whether its patience has elapsed.
        match self.events.last() {
            Some(StaticSessionEvent::Closed(outcome)) => match outcome {
                SessionOutcome::Success(_) => SessionStatus::Completed,
                SessionOutcome::Aborted => SessionStatus::Failed,
            },
            _ if self.patience_elapsed() => SessionStatus::Expired,
            _ => SessionStatus::Active,
        }
    }

    fn patience_elapsed(&self) -> bool {
        self.events
            .iter()
            .find_map(|event| match event {
                StaticSessionEvent::Created(session_context) => Some(session_context.patience),
                _ => None,
            })
            .flatten()
            .map(|patience| patience.elapsed())
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;
    use std::time::SystemTime;

    use payjoin_test_utils::{BoxError, EXAMPLE_URL, PARSED_ORIGINAL_PSBT};

    use super::*;
    use crate::hpke::decrypt_message_a;
    use crate::persist::InMemoryPersister;
    use crate::receive::v2::static_session::{
        StaticReceiverBuilder, StaticSessionEvent as ReceiverSessionEvent,
    };
    use crate::{OhttpKeys, Uri};

    /// Static session V2 Payjoin URI: RK and OH but no EX in the fragment.
    const PJ_STATIC_URI: &str = "bitcoin:2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7?pjos=0&pj=HTTPS://PAYJO.IN/TXJCGKTKXLUUZ%23OH1QYPM59NK2LXXS4890SUAXXYT25Z2VAPHP0X7YEYCJXGWAG6UG9ZU6NQ-RK1Q0DJS3VVDXWQQTLQ8022QGXSX7ML9PHZ6EDSF6AKEWQG758JPS2EV";

    /// The address PARSED_ORIGINAL_PSBT pays, so builders find the payee output.
    fn payee_address() -> bitcoin::Address {
        bitcoin::Address::from_str("2N47mmrWXsNBvQR6k78hWJoTji57zXwNcU7")
            .expect("valid address")
            .assume_checked()
    }

    fn sender_from_static_uri() -> StaticSender<WithReplyKey> {
        StaticSenderBuilder::new(
            PARSED_ORIGINAL_PSBT.clone(),
            Uri::try_from(PJ_STATIC_URI)
                .expect("valid uri")
                .assume_checked()
                .check_pj_supported()
                .expect("payjoin to be supported"),
        )
        .build_recommended(FeeRate::BROADCAST_MIN)
        .expect("build should succeed")
        .save(&InMemoryPersister::default())
        .expect("in-memory persister should not fail")
    }

    fn sender_with_receiver_key(
        receiver_key: &HpkeKeyPair,
        patience: Option<Duration>,
    ) -> StaticSender<WithReplyKey> {
        let pj_param = StaticPjParam::new(
            Url::parse(EXAMPLE_URL).expect("valid url"),
            crate::uri::ShortId::from(receiver_key.public_key()),
            OhttpKeys::decode(&payjoin_test_utils::ohttp_key_config_bytes())
                .expect("valid ohttp keys"),
            receiver_key.public_key().clone(),
        );
        let mut builder = StaticSenderBuilder::from_parts(
            PARSED_ORIGINAL_PSBT.clone(),
            &pj_param,
            &payee_address(),
            None,
        );
        if let Some(patience) = patience {
            builder = builder.with_patience(patience);
        }
        builder
            .build_recommended(FeeRate::BROADCAST_MIN)
            .expect("build should succeed")
            .save(&InMemoryPersister::default())
            .expect("in-memory persister should not fail")
    }

    #[test]
    fn uri_builds_static_sender() {
        let sender = sender_from_static_uri();
        assert_eq!(sender.session_context.patience, None);
    }

    #[test]
    fn post_request_is_one_queue_frame_the_receiver_can_read() -> Result<(), BoxError> {
        let receiver_key = HpkeKeyPair::gen_keypair();
        let sender = sender_with_receiver_key(&receiver_key, None);
        let (req, _ctx) = sender.create_v2_post_request(EXAMPLE_URL)?;
        assert_eq!(req.body.len(), crate::directory::ENCAPSULATED_MESSAGE_BYTES);

        let server = payjoin_test_utils::ohttp_server();
        let (bhttp_bytes, _) = server.decapsulate(&req.body)?;
        let message = bhttp::Message::read_bhttp(&mut std::io::Cursor::new(bhttp_bytes))?;
        assert_eq!(message.control().method(), Some(&b"POST"[..]));
        let expected_path = format!("/q/{}", crate::uri::ShortId::from(receiver_key.public_key()));
        assert_eq!(message.control().path(), Some(expected_path.as_bytes()));

        // The posted body is exactly one queue frame, decryptable by the
        // receiver key from the URI.
        let frame = message.content();
        assert_eq!(frame.len(), crate::directory::QUEUE_FRAME_BYTES);
        let (payload, _reply_key) = decrypt_message_a(frame, receiver_key.secret_key())?;
        assert!(std::str::from_utf8(&payload)?.contains("cHNidP8"));
        Ok(())
    }

    #[test]
    fn poll_request_targets_reply_mailbox_as_standard_v2() -> Result<(), BoxError> {
        let receiver_key = HpkeKeyPair::gen_keypair();
        let sender = sender_with_receiver_key(&receiver_key, None);
        let polling = StaticSender {
            state: PollingForProposal,
            session_context: sender.session_context.clone(),
        };
        let (req, _ctx) = polling.create_poll_request(EXAMPLE_URL)?;

        let server = payjoin_test_utils::ohttp_server();
        let (bhttp_bytes, _) = server.decapsulate(&req.body)?;
        let message = bhttp::Message::read_bhttp(&mut std::io::Cursor::new(bhttp_bytes))?;
        assert_eq!(message.control().method(), Some(&b"GET"[..]));
        let mailbox = crate::uri::ShortId::from(
            HpkeKeyPair::from_secret_key(&sender.session_context.reply_key).public_key(),
        );
        let expected_path = format!("/{mailbox}");
        assert_eq!(message.control().path(), Some(expected_path.as_bytes()));
        Ok(())
    }

    #[test]
    fn elapsed_patience_prompts_fallback() -> Result<(), BoxError> {
        let receiver_key = HpkeKeyPair::gen_keypair();
        let mut sender = sender_with_receiver_key(&receiver_key, None);
        sender.session_context.patience = Some(
            Time::try_from(SystemTime::now() - Duration::from_secs(1))
                .expect("time in the past should be representable"),
        );
        let polling = StaticSender {
            state: PollingForProposal,
            session_context: sender.session_context.clone(),
        };

        let err = match polling.create_poll_request(EXAMPLE_URL) {
            Err(e) => e,
            Ok(_) => panic!("elapsed patience should refuse to poll"),
        };
        assert!(err.is_expired());
        let err = match sender.create_v2_post_request(EXAMPLE_URL) {
            Err(e) => e,
            Ok(_) => panic!("elapsed patience should refuse to post"),
        };
        assert!(err.is_expired());

        // The way out is cancelling into fallback broadcast.
        let persister = InMemoryPersister::<StaticSessionEvent>::default();
        let expected_fallback =
            sender.session_context.psbt_ctx.original_psbt.clone().extract_tx_unchecked_fee_rate();
        let pending = sender.cancel().save(&persister)?;
        assert_eq!(pending.fallback_tx(), &expected_fallback);
        pending.close().save(&persister)?;
        assert!(persister.inner.lock().expect("lock should not be poisoned").is_closed);
        Ok(())
    }

    #[test]
    fn no_patience_polls_indefinitely() -> Result<(), BoxError> {
        let receiver_key = HpkeKeyPair::gen_keypair();
        let sender = sender_with_receiver_key(&receiver_key, None);
        let polling =
            StaticSender { state: PollingForProposal, session_context: sender.session_context };
        assert!(polling.create_poll_request(EXAMPLE_URL).is_ok());
        Ok(())
    }

    #[test]
    fn replay_reconstructs_session_states() -> Result<(), BoxError> {
        let receiver_key = HpkeKeyPair::gen_keypair();
        let sender = sender_with_receiver_key(&receiver_key, None);
        let persister = InMemoryPersister::<StaticSessionEvent>::default();
        persister
            .save_event(StaticSessionEvent::Created(Box::new(sender.session_context.clone())))
            .expect("in-memory persister should not fail");

        let (state, history) = replay_static_event_log(&persister)?;
        assert_eq!(state, StaticSendSession::WithReplyKey(sender.clone()));
        assert_eq!(history.status(), SessionStatus::Active);
        assert_eq!(history.pj_param(), &sender.session_context.pj_param);

        persister
            .save_event(StaticSessionEvent::PostedOriginalPsbt())
            .expect("in-memory persister should not fail");
        let (state, _) = replay_static_event_log(&persister)?;
        assert!(matches!(state, StaticSendSession::PollingForProposal(_)));

        persister
            .save_event(StaticSessionEvent::Cancelled())
            .expect("in-memory persister should not fail");
        let (state, _) = replay_static_event_log(&persister)?;
        assert!(matches!(state, StaticSendSession::PendingFallback(_)));

        persister
            .save_event(StaticSessionEvent::Closed(SessionOutcome::Aborted))
            .expect("in-memory persister should not fail");
        let (state, history) = replay_static_event_log(&persister)?;
        assert!(matches!(state, StaticSendSession::Closed(SessionOutcome::Aborted)));
        assert_eq!(history.status(), SessionStatus::Failed);
        Ok(())
    }

    #[test]
    fn replay_with_elapsed_patience_stays_live_and_reports_expired() -> Result<(), BoxError> {
        let receiver_key = HpkeKeyPair::gen_keypair();
        let mut sender = sender_with_receiver_key(&receiver_key, None);
        sender.session_context.patience = Some(
            Time::try_from(SystemTime::now() - Duration::from_secs(1))
                .expect("time in the past should be representable"),
        );

        let persister = InMemoryPersister::<StaticSessionEvent>::default();
        persister
            .save_event(StaticSessionEvent::Created(Box::new(sender.session_context.clone())))
            .expect("in-memory persister should not fail");

        // The session replays live so the caller can still cancel into
        // fallback; only the status reports the elapsed patience.
        let (state, history) = replay_static_event_log(&persister)?;
        assert_eq!(state, StaticSendSession::WithReplyKey(sender));
        assert_eq!(history.status(), SessionStatus::Expired);
        Ok(())
    }

    #[test]
    fn end_to_end_static_sender_reaches_static_receiver() -> Result<(), BoxError> {
        // The receiver's queue and the sender's POST must agree on
        // derivation from the same URI.
        let rx_persister = InMemoryPersister::<ReceiverSessionEvent>::default();
        let receiver = StaticReceiverBuilder::new(
            payee_address(),
            EXAMPLE_URL,
            OhttpKeys::decode(&payjoin_test_utils::ohttp_key_config_bytes())
                .expect("valid ohttp keys"),
            HpkeKeyPair::gen_keypair(),
        )?
        .build()
        .save(&rx_persister)
        .expect("in-memory persister should not fail");

        let uri = receiver.pj_uri().to_string();
        let uri = Uri::try_from(uri.as_str())?
            .assume_checked()
            .check_pj_supported()
            .expect("static URI supports payjoin");
        let sender = StaticSenderBuilder::new(PARSED_ORIGINAL_PSBT.clone(), uri)
            .build_recommended(FeeRate::BROADCAST_MIN)?
            .save(&InMemoryPersister::default())
            .expect("in-memory persister should not fail");

        let (req, _) = sender.create_v2_post_request(EXAMPLE_URL)?;
        let server = payjoin_test_utils::ohttp_server();
        let (bhttp_bytes, _) = server.decapsulate(&req.body)?;
        let message = bhttp::Message::read_bhttp(&mut std::io::Cursor::new(bhttp_bytes))?;

        // The sender posts to the same queue the receiver polls.
        let (poll_req, _) = receiver.create_poll_request(EXAMPLE_URL)?;
        let (poll_bytes, _) = server.decapsulate(&poll_req.body)?;
        let poll_message = bhttp::Message::read_bhttp(&mut std::io::Cursor::new(poll_bytes))?;
        let post_path = String::from_utf8(message.control().path().expect("path").to_vec())?;
        let poll_path = String::from_utf8(poll_message.control().path().expect("path").to_vec())?;
        assert_eq!(Some(post_path.as_str()), poll_path.strip_suffix("?after=0"));
        Ok(())
    }

    #[test]
    fn static_sender_event_serialization_roundtrip() -> Result<(), BoxError> {
        let receiver_key = HpkeKeyPair::gen_keypair();
        let sender = sender_with_receiver_key(&receiver_key, Some(Duration::from_secs(60)));
        let test_cases = vec![
            StaticSessionEvent::Created(Box::new(sender.session_context.clone())),
            StaticSessionEvent::PostedOriginalPsbt(),
            StaticSessionEvent::Cancelled(),
            StaticSessionEvent::Closed(SessionOutcome::Success(PARSED_ORIGINAL_PSBT.clone())),
            StaticSessionEvent::Closed(SessionOutcome::Aborted),
        ];
        for event in test_cases {
            let serialized = serde_json::to_string(&event)?;
            let deserialized: StaticSessionEvent = serde_json::from_str(&serialized)?;
            assert_eq!(event, deserialized);
        }
        Ok(())
    }
}
