use std::fmt::{self, Display};

use serde::{Deserialize, Serialize};

use super::{Receiver, SessionContext, WithContext};
use crate::persist::{self};
use crate::receive::v1;
use crate::uri::ShortId;

/// Opaque key type for the receiver
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverToken(ShortId);

impl Display for ReceiverToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "{}", self.0) }
}

impl From<Receiver<WithContext>> for ReceiverToken {
    fn from(receiver: Receiver<WithContext>) -> Self { ReceiverToken(receiver.context.id()) }
}

impl AsRef<[u8]> for ReceiverToken {
    fn as_ref(&self) -> &[u8] { self.0.as_bytes() }
}

impl persist::Value for Receiver<WithContext> {
    type Key = ReceiverToken;

    fn key(&self) -> Self::Key { ReceiverToken(self.context.id()) }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
/// Represents a piece of information that the reciever has obtained from the session
/// Each event can be used to transition the receiver state machine to a new state
pub enum ReceiverSessionEvent {
    Created(SessionContext),
    UncheckedProposal(v1::UncheckedProposal),
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
    SessionInvalid(String),
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
            ReceiverSessionEvent::UncheckedProposal(unchecked_proposal.clone()),
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
