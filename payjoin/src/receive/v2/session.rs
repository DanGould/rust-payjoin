use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use super::{Receiver, ReceiverTypeState, SessionContext, UninitializedReceiver};
use crate::output_substitution::OutputSubstitution;
use crate::persist::SessionPersister;
use crate::receive::v2::subdir;
use crate::receive::{v1, JsonReply};
use crate::{HpkePublicKey, ImplementationError, PjUri};

/// Errors that can occur when replaying a receiver event log
#[derive(Debug)]
pub struct ReceiverReplayError(InternalReceiverReplayError);

impl std::fmt::Display for ReceiverReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use InternalReceiverReplayError::*;
        match &self.0 {
            SessionExpired(expiry) => write!(f, "Session expired at {expiry:?}"),
            InvalidStateAndEvent(state, event) => write!(
                f,
                "Invalid combination of state ({state:?}) and event ({event:?}) during replay",
            ),
            PersistenceFailure(e) => write!(f, "Persistence failure: {e}"),
        }
    }
}
impl std::error::Error for ReceiverReplayError {}

impl From<InternalReceiverReplayError> for ReceiverReplayError {
    fn from(e: InternalReceiverReplayError) -> Self { ReceiverReplayError(e) }
}

#[derive(Debug)]
pub(crate) enum InternalReceiverReplayError {
    /// Session expired
    SessionExpired(SystemTime),
    /// Invalid combination of state and event
    InvalidStateAndEvent(Box<ReceiverTypeState>, Box<ReceiverSessionEvent>),
    /// Application storage error
    PersistenceFailure(ImplementationError),
}

/// Replay a receiver event log to get the receiver in its current state [ReceiverTypeState]
/// and a session history [SessionHistory]
pub fn replay_receiver_event_log<P>(
    persister: &P,
) -> Result<(ReceiverTypeState, SessionHistory), ReceiverReplayError>
where
    P: SessionPersister,
    P::SessionEvent: From<ReceiverSessionEvent> + Clone,
    ReceiverSessionEvent: From<P::SessionEvent>,
{
    let logs = persister
        .load()
        .map_err(|e| InternalReceiverReplayError::PersistenceFailure(Box::new(e).into()))?;
    let mut receiver =
        ReceiverTypeState::Uninitialized(Receiver { state: UninitializedReceiver {} });
    let mut history = SessionHistory::default();

    for log in logs {
        history.events.push(log.clone().into());
        match receiver.process_event(log.into()) {
            Ok(next_receiver) => {
                receiver = next_receiver;
            }
            Err(e) => {
                // All error cases are terminal. Close the session in its current state
                persister.close().map_err(|storage_err| {
                    InternalReceiverReplayError::PersistenceFailure(Box::new(storage_err))
                })?;

                return Err(e);
            }
        }
    }

    Ok((receiver, history))
}

#[derive(Default, Clone)]
pub struct SessionHistory {
    events: Vec<ReceiverSessionEvent>,
}

impl SessionHistory {
    pub fn pj_uri<'a>(&self) -> Option<PjUri<'a>> {
        self.events.iter().find_map(|event| match event {
            ReceiverSessionEvent::Created(session_context) => {
                // TODO this code was copied from ReceiverWithContext::pj_uri. Should be deduped
                use crate::uri::{PayjoinExtras, UrlExt};
                let id = session_context.id();
                let mut pj = subdir(&session_context.directory, &id).clone();
                pj.set_receiver_pubkey(session_context.s.public_key().clone());
                pj.set_ohttp(session_context.ohttp_keys.clone());
                pj.set_exp(session_context.expiry);
                let extras = PayjoinExtras {
                    endpoint: pj,
                    output_substitution: OutputSubstitution::Disabled,
                };
                Some(bitcoin_uri::Uri::with_extras(session_context.address.clone(), extras))
            }
            _ => None,
        })
    }

    pub fn payment_amount(&self) -> Option<bitcoin::Amount> { self.pj_uri().map(|uri| uri.amount)? }

    pub fn payment_address(&self) -> Option<bitcoin::Address<bitcoin::address::NetworkChecked>> {
        self.pj_uri().map(|uri| uri.address)
    }

    pub fn fallback_txid(&self) -> Option<bitcoin::Txid> {
        self.events.iter().find_map(|event| match event {
            ReceiverSessionEvent::UncheckedProposal((proposal, _)) =>
                Some(proposal.psbt.unsigned_tx.compute_txid()),
            _ => None,
        })
    }

    pub fn original_psbt(&self) -> Option<bitcoin::Psbt> {
        self.events.iter().find_map(|event| match event {
            ReceiverSessionEvent::UncheckedProposal((proposal, _)) => Some(proposal.psbt.clone()),
            _ => None,
        })
    }

    pub fn proposed_payjoin_psbt(&self) -> Option<bitcoin::Psbt> {
        self.events.iter().find_map(|event| match event {
            ReceiverSessionEvent::PayjoinProposal(proposal) => Some(proposal.psbt().clone()),
            _ => None,
        })
    }

    pub fn psbt_with_contributed_inputs(&self) -> Option<bitcoin::Psbt> {
        self.events.iter().find_map(|event| match event {
            ReceiverSessionEvent::ProvisionalProposal(proposal) => Some(proposal.psbt()),
            _ => None,
        })
    }

    pub fn terminal_error(&self) -> Option<(String, Option<JsonReply>)> {
        self.events.iter().find_map(|event| match event {
            ReceiverSessionEvent::SessionInvalid(err_str, reply) =>
                Some((err_str.clone(), reply.clone())),
            _ => None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Represents a specific state change that has occurred during the receiver's session.
/// Each event can be used to transition the receiver state machine to a new state
pub enum ReceiverSessionEvent {
    Created(SessionContext),
    UncheckedProposal((v1::UncheckedProposal, Option<HpkePublicKey>)),
    MaybeInputsOwned(v1::MaybeInputsOwned),
    MaybeInputsSeen(v1::MaybeInputsSeen),
    OutputsUnknown(v1::OutputsUnknown),
    WantsOutputs(v1::WantsOutputs),
    WantsInputs(v1::WantsInputs),
    ProvisionalProposal(v1::ProvisionalProposal),
    PayjoinProposal(v1::PayjoinProposal),
    /// Session is invalid. This is a irrecoverable error. Fallback tx should be broadcasted.
    /// TODO this should be any error type that is impl std::error and works well with serde, or as a fallback can be formatted as a string
    /// Reason being in some cases we still want to preserve the error b/c we can action on it. For now this is a terminal state and there is nothing to replay and is saved to be displayed.
    /// b/c its a terminal state and there is nothing to replay. So serialization will be lossy and that is fine.
    SessionInvalid(String, Option<JsonReply>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receive::v1::test::{
        maybe_inputs_owned_from_test_vector, maybe_inputs_seen_from_test_vector,
        outputs_unknown_from_test_vector, payjoin_proposal_from_test_vector,
        provisional_proposal_from_test_vector, unchecked_proposal_from_test_vector,
        wants_inputs_from_test_vector, wants_outputs_from_test_vector,
    };
    use crate::receive::v2::test::SHARED_CONTEXT;

    #[test]
    fn test_receiver_session_event_serialization() {
        let event = ReceiverSessionEvent::Created(SHARED_CONTEXT.clone());
        let serialized = serde_json::to_string(&event).unwrap();
        let deserialized: ReceiverSessionEvent = serde_json::from_str(&serialized).unwrap();

        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_session_event_serialization_roundtrip() {
        let unchecked_proposal = unchecked_proposal_from_test_vector();
        let test_cases = vec![
            ReceiverSessionEvent::UncheckedProposal((unchecked_proposal.clone(), None)),
            ReceiverSessionEvent::MaybeInputsOwned(maybe_inputs_owned_from_test_vector()),
            ReceiverSessionEvent::MaybeInputsSeen(maybe_inputs_seen_from_test_vector()),
            ReceiverSessionEvent::OutputsUnknown(outputs_unknown_from_test_vector()),
            ReceiverSessionEvent::WantsOutputs(wants_outputs_from_test_vector(
                unchecked_proposal.clone(),
            )),
            ReceiverSessionEvent::WantsInputs(wants_inputs_from_test_vector()),
            ReceiverSessionEvent::ProvisionalProposal(provisional_proposal_from_test_vector(
                unchecked_proposal.clone(),
            )),
            ReceiverSessionEvent::PayjoinProposal(payjoin_proposal_from_test_vector(
                unchecked_proposal.clone(),
            )),
        ];
        for event in test_cases {
            let serialized = serde_json::to_string(&event).unwrap();
            let deserialized: ReceiverSessionEvent = serde_json::from_str(&serialized).unwrap();
            assert_eq!(event, deserialized);
        }
    }
}
