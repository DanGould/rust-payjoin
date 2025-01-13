use std::str::FromStr;
use std::time::{Duration, SystemTime};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::Psbt;
use bitcoin::{Address, FeeRate, OutPoint, Script, TxOut};
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use url::Url;

use super::error::InternalRequestError;
use super::v2::error::{InternalSessionError, SessionError};
use super::{
    v1, Error, InputContributionError, OutputSubstitutionError, RequestError, SelectionError,
};
use crate::hpke::{decrypt_message_a, encrypt_message_b, HpkeKeyPair, HpkePublicKey};
use crate::ohttp::{ohttp_decapsulate, ohttp_encapsulate, OhttpEncapsulationError, OhttpKeys};
use crate::psbt::PsbtExt;
use crate::receive::optional_parameters::Params;
use crate::receive::InputPair;
use crate::uri::ShortId;
use crate::Request;

pub(crate) mod error;

const SUPPORTED_VERSIONS: &[usize] = &[1, 2];

static TWENTY_FOUR_HOURS_DEFAULT_EXPIRY: Duration = Duration::from_secs(60 * 60 * 24);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SessionContext {
    #[serde(deserialize_with = "deserialize_address_assume_checked")]
    address: Address,
    directory: url::Url,
    subdirectory: Option<url::Url>,
    ohttp_keys: OhttpKeys,
    expiry: SystemTime,
    ohttp_relay: url::Url,
    s: HpkeKeyPair,
    e: Option<HpkePublicKey>,
}

fn deserialize_address_assume_checked<'de, D>(deserializer: D) -> Result<Address, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    let address = Address::from_str(&s).map_err(serde::de::Error::custom)?;
    Ok(address.assume_checked())
}

fn subdir_path_from_pubkey(pubkey: &HpkePublicKey) -> ShortId {
    sha256::Hash::hash(&pubkey.to_compressed_bytes()).into()
}

#[derive(Debug, Clone)]
pub struct InitialState;

pub trait State {}

impl State for InitialState {}

macro_rules! impl_state_wrapper {
    ($inner:ident) => {
        #[derive(Debug, Clone)]
        pub struct $inner(v1::$inner);
        impl State for $inner {}
    };
}

impl_state_wrapper!(UncheckedProposal);
impl_state_wrapper!(MaybeInputsOwned);
impl_state_wrapper!(MaybeInputsSeen);
impl_state_wrapper!(OutputsUnknown);
impl_state_wrapper!(WantsOutputs);
impl_state_wrapper!(WantsInputs);
impl_state_wrapper!(ProvisionalProposal);
impl_state_wrapper!(PayjoinProposal);

// Main Receiver type that holds both context and state
#[derive(Debug, Clone)]
pub struct Receiver<S: State> {
    context: SessionContext,
    state: S,
}

impl<S: State> Receiver<S> {
    pub fn extract_err_req(
        &mut self,
        err: Error,
    ) -> Result<(Request, ohttp::ClientResponse), SessionError> {
        let subdir = self.subdir();
        let (body, ohttp_ctx) = ohttp_encapsulate(
            &mut self.context.ohttp_keys,
            "POST",
            subdir.as_str(),
            Some(err.to_json().as_bytes()),
        )
        .map_err(InternalSessionError::OhttpEncapsulation)?;
        let url = self.subdir();
        let req = Request::new_v2(url, body);
        Ok((req, ohttp_ctx))
    }

    /// Build a V2 Payjoin URI from the receiver's context
    pub fn pj_uri<'a>(&self) -> crate::PjUri<'a> {
        use crate::uri::{PayjoinExtras, UrlExt};
        let mut pj = self.subdir().clone();
        pj.set_receiver_pubkey(self.context.s.public_key().clone());
        pj.set_ohttp(self.context.ohttp_keys.clone());
        pj.set_exp(self.context.expiry);
        let extras = PayjoinExtras { endpoint: pj, disable_output_substitution: false };
        bitcoin_uri::Uri::with_extras(self.context.address.clone(), extras)
    }

    /// The subdirectory for this Payjoin receiver session.
    /// It consists of a directory URL and the session ShortID in the path.
    pub fn subdir(&self) -> Url {
        let mut url = self.context.directory.clone();
        {
            let mut path_segments =
                url.path_segments_mut().expect("Payjoin Directory URL cannot be a base");
            path_segments.push(&self.id().to_string());
        }
        url
    }

    /// The per-session identifier
    pub fn id(&self) -> ShortId {
        sha256::Hash::hash(&self.context.s.public_key().to_compressed_bytes()).into()
    }
}

// Only implement serialization for the initial state
impl Serialize for Receiver<InitialState> {
    fn serialize<Ser>(&self, serializer: Ser) -> Result<Ser::Ok, Ser::Error>
    where
        Ser: serde::Serializer,
    {
        self.context.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Receiver<InitialState> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let context = SessionContext::deserialize(deserializer)?;
        Ok(Self { context, state: InitialState })
    }
}

// Initial Receiver implementation without state
impl Receiver<InitialState> {
    /// Creates a new `Receiver` with the provided parameters.
    ///
    /// # Parameters
    /// - `address`: The Bitcoin address for the payjoin session.
    /// - `directory`: The URL of the store-and-forward payjoin directory.
    /// - `ohttp_keys`: The OHTTP keys used for encrypting and decrypting HTTP requests and responses.
    /// - `ohttp_relay`: The URL of the OHTTP relay, used to keep client IP address confidential.
    /// - `expire_after`: The duration after which the session expires.
    ///
    /// # Returns
    /// A new instance of `Receiver`.
    ///
    /// # References
    /// - [BIP 77: Payjoin Version 2: Serverless Payjoin](https://github.com/bitcoin/bips/pull/1483)
    pub fn new(
        address: Address,
        directory: Url,
        ohttp_keys: OhttpKeys,
        ohttp_relay: Url,
        expire_after: Option<Duration>,
    ) -> Self {
        Self {
            context: SessionContext {
                address,
                directory,
                subdirectory: None,
                ohttp_keys,
                ohttp_relay,
                expiry: SystemTime::now()
                    + expire_after.unwrap_or(TWENTY_FOUR_HOURS_DEFAULT_EXPIRY),
                s: HpkeKeyPair::gen_keypair(),
                e: None,
            },
            state: InitialState,
        }
    }

    /// Extract an OHTTP Encapsulated HTTP GET request for the Original PSBT
    pub fn extract_req(&mut self) -> Result<(Request, ohttp::ClientResponse), SessionError> {
        if SystemTime::now() > self.context.expiry {
            return Err(InternalSessionError::Expired(self.context.expiry).into());
        }
        let (body, ohttp_ctx) =
            self.fallback_req_body().map_err(InternalSessionError::OhttpEncapsulation)?;
        let url = self.context.ohttp_relay.clone();
        let req = Request::new_v2(url, body);
        Ok((req, ohttp_ctx))
    }

    /// The response can either be an UncheckedProposal or an ACCEPTED message
    /// indicating no UncheckedProposal is available yet.
    pub fn process_res(
        &mut self,
        body: &[u8],
        context: ohttp::ClientResponse,
    ) -> Result<Option<Receiver<UncheckedProposal>>, Error> {
        let response_array: &[u8; crate::ohttp::ENCAPSULATED_MESSAGE_BYTES] =
            body.try_into().map_err(|_| {
                Error::Server(Box::new(SessionError::from(
                    InternalSessionError::UnexpectedResponseSize(body.len()),
                )))
            })?;
        log::trace!("decapsulating directory response");
        let response = ohttp_decapsulate(context, response_array)?;
        if response.body().is_empty() {
            log::debug!("response is empty");
            return Ok(None);
        }
        match String::from_utf8(response.body().to_vec()) {
            // V1 response bodies are utf8 plaintext
            Ok(response) => Ok(Some(self.extract_proposal_from_v1(response)?)),
            // V2 response bodies are encrypted binary
            Err(_) => Ok(Some(self.extract_proposal_from_v2(response.body().to_vec())?)),
        }
    }

    fn fallback_req_body(
        &mut self,
    ) -> Result<
        ([u8; crate::ohttp::ENCAPSULATED_MESSAGE_BYTES], ohttp::ClientResponse),
        OhttpEncapsulationError,
    > {
        let fallback_target = self.subdir();
        ohttp_encapsulate(&mut self.context.ohttp_keys, "GET", fallback_target.as_str(), None)
    }

    fn extract_proposal_from_v1(
        &mut self,
        response: String,
    ) -> Result<Receiver<UncheckedProposal>, Error> {
        Ok(Receiver {
            context: self.context.clone(),
            state: UncheckedProposal(self.unchecked_from_payload(response)?),
        })
    }

    fn extract_proposal_from_v2(
        &mut self,
        response: Vec<u8>,
    ) -> Result<Receiver<UncheckedProposal>, Error> {
        let (payload_bytes, e) = decrypt_message_a(&response, self.context.s.secret_key().clone())?;
        self.context.e = Some(e);
        let payload = String::from_utf8(payload_bytes).map_err(InternalRequestError::Utf8)?;
        Ok(Receiver {
            context: self.context.clone(),
            state: UncheckedProposal(self.unchecked_from_payload(payload)?),
        })
    }

    fn unchecked_from_payload(
        &mut self,
        payload: String,
    ) -> Result<v1::UncheckedProposal, RequestError> {
        let (base64, padded_query) = payload.split_once('\n').unwrap_or_default();
        let query = padded_query.trim_matches('\0');
        log::trace!("Received query: {}, base64: {}", query, base64);
        let unchecked_psbt = Psbt::from_str(base64).map_err(InternalRequestError::ParsePsbt)?;
        let psbt = unchecked_psbt.validate().map_err(InternalRequestError::InconsistentPsbt)?;
        log::debug!("Received original psbt: {:?}", psbt);
        let mut params = Params::from_query_pairs(
            url::form_urlencoded::parse(query.as_bytes()),
            SUPPORTED_VERSIONS,
        )
        .map_err(InternalRequestError::SenderParams)?;

        // Output substitution must be disabled for V1 sessions in V2 contexts.
        //
        // V2 contexts depend on a payjoin directory to store and forward payjoin
        // proposals. Plaintext V1 proposals are vulnerable to output replacement
        // attacks by a malicious directory if output substitution is not disabled.
        // V2 proposals are authenticated and encrypted to prevent such attacks.
        //
        // see: https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki#unsecured-payjoin-server
        if params.v == 1 {
            params.disable_output_substitution = true;
        }

        log::debug!("Received request with params: {:?}", params);
        Ok(v1::UncheckedProposal { psbt, params })
    }
}

// Implement state transitions for UncheckedState
impl Receiver<UncheckedProposal> {
    /// The Sender's Original PSBT
    pub fn extract_tx_to_schedule_broadcast(&self) -> bitcoin::Transaction {
        self.state.0.extract_tx_to_schedule_broadcast()
    }

    /// Call after checking that the Original PSBT can be broadcast.
    ///
    /// Receiver MUST check that the Original PSBT from the sender
    /// can be broadcast, i.e. `testmempoolaccept` bitcoind rpc returns { "allowed": true,.. }
    /// for `extract_tx_to_schedule_broadcast()` before calling this method.
    ///
    /// Do this check if you generate bitcoin uri to receive Payjoin on sender request without manual human approval, like a payment processor.
    /// Such so called "non-interactive" receivers are otherwise vulnerable to probing attacks.
    /// If a sender can make requests at will, they can learn which bitcoin the receiver owns at no cost.
    /// Broadcasting the Original PSBT after some time in the failure case makes incurs sender cost and prevents probing.
    ///
    /// Call this after checking downstream.
    pub fn check_broadcast_suitability(
        self,
        min_fee_rate: Option<FeeRate>,
        can_broadcast: impl Fn(&bitcoin::Transaction) -> Result<bool, Error>,
    ) -> Result<Receiver<MaybeInputsOwned>, Error> {
        let state = self.state.0.check_broadcast_suitability(min_fee_rate, can_broadcast)?;
        Ok(Receiver { context: self.context, state: MaybeInputsOwned(state) })
    }

    /// Call this method if the only way to initiate a Payjoin with this receiver
    /// requires manual intervention, as in most consumer wallets.
    ///
    /// So-called "non-interactive" receivers, like payment processors, that allow arbitrary requests are otherwise vulnerable to probing attacks.
    /// Those receivers call `extract_tx_to_check_broadcast()` and `attest_tested_and_scheduled_broadcast()` after making those checks downstream.
    pub fn assume_interactive_receiver(self) -> Receiver<MaybeInputsOwned> {
        let state = self.state.0.assume_interactive_receiver();
        Receiver { context: self.context, state: MaybeInputsOwned(state) }
    }
}

// Implement state transitions for MaybeInputsOwnedState
impl Receiver<MaybeInputsOwned> {
    /// Check that the Original PSBT has no receiver-owned inputs.
    /// Return original-psbt-rejected error or otherwise refuse to sign undesirable inputs.
    ///
    /// An attacker could try to spend receiver's own inputs. This check prevents that.
    pub fn check_inputs_not_owned(
        self,
        is_owned: impl Fn(&Script) -> Result<bool, Error>,
    ) -> Result<Receiver<MaybeInputsSeen>, Error> {
        let state = self.state.0.check_inputs_not_owned(is_owned)?;
        Ok(Receiver { context: self.context, state: MaybeInputsSeen(state) })
    }
}

// Implement state transitions for MaybeInputsSeenState
impl Receiver<MaybeInputsSeen> {
    /// Make sure that the original transaction inputs have never been seen before.
    /// This prevents probing attacks. This prevents reentrant Payjoin, where a sender
    /// proposes a Payjoin PSBT as a new Original PSBT for a new Payjoin.
    pub fn check_no_inputs_seen_before(
        self,
        is_known: impl Fn(&OutPoint) -> Result<bool, Error>,
    ) -> Result<Receiver<OutputsUnknown>, Error> {
        let state = self.state.0.check_no_inputs_seen_before(is_known)?;
        Ok(Receiver { context: self.context, state: OutputsUnknown(state) })
    }
}

// Implement state transitions for OutputsUnknownState
impl Receiver<OutputsUnknown> {
    /// Find which outputs belong to the receiver
    pub fn identify_receiver_outputs(
        self,
        is_receiver_output: impl Fn(&Script) -> Result<bool, Error>,
    ) -> Result<Receiver<WantsOutputs>, Error> {
        let state = self.state.0.identify_receiver_outputs(is_receiver_output)?;
        Ok(Receiver { context: self.context, state: WantsOutputs(state) })
    }
}

// Implement state transitions for WantsOutputsState
impl Receiver<WantsOutputs> {
    pub fn is_output_substitution_disabled(&self) -> bool {
        self.state.0.is_output_substitution_disabled()
    }

    /// Substitute the receiver output script with the provided script.
    pub fn substitute_receiver_script(
        self,
        output_script: &Script,
    ) -> Result<Receiver<WantsOutputs>, OutputSubstitutionError> {
        let state = self.state.0.substitute_receiver_script(output_script)?;
        Ok(Receiver { context: self.context, state: WantsOutputs(state) })
    }

    /// Replace **all** receiver outputs with one or more provided outputs.
    /// The drain script specifies which address to *drain* coins to. An output corresponding to
    /// that address must be included in `replacement_outputs`. The value of that output may be
    /// increased or decreased depending on the receiver's input contributions and whether the
    /// receiver needs to pay for additional miner fees (e.g. in the case of adding many outputs).
    pub fn replace_receiver_outputs(
        self,
        replacement_outputs: Vec<TxOut>,
        drain_script: &Script,
    ) -> Result<Receiver<WantsOutputs>, OutputSubstitutionError> {
        let state = self.state.0.replace_receiver_outputs(replacement_outputs, drain_script)?;
        Ok(Receiver { context: self.context, state: WantsOutputs(state) })
    }

    /// Proceed to the input contribution step.
    /// Outputs cannot be modified after this function is called.
    pub fn commit_outputs(self) -> Receiver<WantsInputs> {
        let state = self.state.0.commit_outputs();
        Receiver { context: self.context, state: WantsInputs(state) }
    }
}

// Implement state transitions for WantsInputsState
impl Receiver<WantsInputs> {
    /// Select receiver input such that the payjoin avoids surveillance.
    /// Return the input chosen that has been applied to the Proposal.
    ///
    /// Proper coin selection allows payjoin to resemble ordinary transactions.
    /// To ensure the resemblance, a number of heuristics must be avoided.
    ///
    /// UIH "Unnecessary input heuristic" is one class of them to avoid. We define
    /// UIH1 and UIH2 according to the BlockSci practice
    /// BlockSci UIH1 and UIH2:
    /// if min(in) > min(out) then UIH1 else UIH2
    /// <https://eprint.iacr.org/2022/589.pdf>
    pub fn try_preserving_privacy(
        &self,
        candidate_inputs: impl IntoIterator<Item = InputPair>,
    ) -> Result<InputPair, SelectionError> {
        self.state.0.try_preserving_privacy(candidate_inputs)
    }

    /// Add the provided list of inputs to the transaction.
    /// Any excess input amount is added to the change_vout output indicated previously.
    pub fn contribute_inputs(
        self,
        inputs: impl IntoIterator<Item = InputPair>,
    ) -> Result<Receiver<WantsInputs>, InputContributionError> {
        let state = self.state.0.contribute_inputs(inputs)?;
        Ok(Receiver { context: self.context, state: WantsInputs(state) })
    }

    /// Proceed to the proposal finalization step.
    /// Inputs cannot be modified after this function is called.
    pub fn commit_inputs(self) -> Receiver<ProvisionalProposal> {
        let state = self.state.0.commit_inputs();
        Receiver { context: self.context, state: ProvisionalProposal(state) }
    }
}

// Implement state transitions for ProvisionalProposalState
impl Receiver<ProvisionalProposal> {
    pub fn finalize_proposal(
        self,
        wallet_process_psbt: impl Fn(&Psbt) -> Result<Psbt, Error>,
        min_feerate_sat_per_vb: Option<FeeRate>,
        max_feerate_sat_per_vb: FeeRate,
    ) -> Result<Receiver<PayjoinProposal>, Error> {
        let state = self.state.0.finalize_proposal(
            wallet_process_psbt,
            min_feerate_sat_per_vb,
            max_feerate_sat_per_vb,
        )?;
        Ok(Receiver { context: self.context, state: PayjoinProposal(state) })
    }
}

// Implement state transitions for PayjoinProposalState
impl Receiver<PayjoinProposal> {
    pub fn utxos_to_be_locked(&self) -> impl '_ + Iterator<Item = &bitcoin::OutPoint> {
        self.state.0.utxos_to_be_locked()
    }

    pub fn is_output_substitution_disabled(&self) -> bool {
        self.state.0.is_output_substitution_disabled()
    }

    pub fn psbt(&self) -> &Psbt { self.state.0.psbt() }

    #[cfg(feature = "v2")]
    pub fn extract_v2_req(&mut self) -> Result<(Request, ohttp::ClientResponse), Error> {
        let target_resource: Url;
        let body: Vec<u8>;
        let method: &str;

        if let Some(e) = &self.context.e {
            // Prepare v2 payload
            let payjoin_bytes = self.state.0.psbt().serialize();
            let sender_subdir = subdir_path_from_pubkey(e);
            target_resource = self
                .context
                .directory
                .join(&sender_subdir.to_string())
                .map_err(|e| Error::Server(e.into()))?;
            body = encrypt_message_b(payjoin_bytes, &self.context.s, e)?;
            method = "POST";
        } else {
            // Prepare v2 wrapped and backwards-compatible v1 payload
            body = self.state.0.psbt().to_string().as_bytes().to_vec();
            let receiver_subdir = subdir_path_from_pubkey(self.context.s.public_key());
            target_resource = self
                .context
                .directory
                .join(&receiver_subdir.to_string())
                .map_err(|e| Error::Server(e.into()))?;
            method = "PUT";
        }
        log::debug!("Payjoin PSBT target: {}", target_resource.as_str());
        let (body, ctx) = ohttp_encapsulate(
            &mut self.context.ohttp_keys,
            method,
            target_resource.as_str(),
            Some(&body),
        )?;
        let url = self.context.ohttp_relay.clone();
        let req = Request::new_v2(url, body);
        Ok((req, ctx))
    }

    #[cfg(feature = "v2")]
    /// Processes the response for the final POST message from the receiver client in the v2 Payjoin protocol.
    ///
    /// This function decapsulates the response using the provided OHTTP context. If the response status is successful,
    /// it indicates that the Payjoin proposal has been accepted. Otherwise, it returns an error with the status code.
    ///
    /// After this function is called, the receiver can either wait for the Payjoin transaction to be broadcast or
    /// choose to broadcast the original PSBT.
    pub fn process_res(
        &self,
        res: &[u8],
        ohttp_context: ohttp::ClientResponse,
    ) -> Result<(), Error> {
        let response_array: &[u8; crate::ohttp::ENCAPSULATED_MESSAGE_BYTES] =
            res.try_into().map_err(|_| {
                Error::Server(Box::new(SessionError::from(
                    InternalSessionError::UnexpectedResponseSize(res.len()),
                )))
            })?;
        let res = ohttp_decapsulate(ohttp_context, response_array)?;
        if res.status().is_success() {
            Ok(())
        } else {
            Err(Error::Server(
                format!("Payjoin Post failed, expected Success status, got {}", res.status())
                    .into(),
            ))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[cfg(feature = "v2")]
    fn receiver_ser_de_roundtrip() {
        use ohttp::hpke::{Aead, Kdf, Kem};
        use ohttp::{KeyId, SymmetricSuite};
        const KEY_ID: KeyId = 1;
        const KEM: Kem = Kem::K256Sha256;
        const SYMMETRIC: &[SymmetricSuite] =
            &[ohttp::SymmetricSuite::new(Kdf::HkdfSha256, Aead::ChaCha20Poly1305)];

        let session = Receiver {
            context: SessionContext {
                address: Address::from_str("tb1q6d3a2w975yny0asuvd9a67ner4nks58ff0q8g4")
                    .unwrap()
                    .assume_checked(),
                directory: url::Url::parse("https://directory.com").unwrap(),
                subdirectory: None,
                ohttp_keys: OhttpKeys(
                    ohttp::KeyConfig::new(KEY_ID, KEM, Vec::from(SYMMETRIC)).unwrap(),
                ),
                ohttp_relay: url::Url::parse("https://relay.com").unwrap(),
                expiry: SystemTime::now() + Duration::from_secs(60),
                s: HpkeKeyPair::gen_keypair(),
                e: None,
            },
            state: InitialState,
        };
        let serialized = serde_json::to_string(&session).unwrap();
        let deserialized: Receiver<InitialState> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(session.context, deserialized.context);
    }

    #[test]
    fn test_v2_pj_uri() {
        let address = bitcoin::Address::from_str("12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX")
            .unwrap()
            .assume_checked();
        let receiver_keys = crate::hpke::HpkeKeyPair::gen_keypair();
        let ohttp_keys =
            OhttpKeys::from_str("OH1QYPM5JXYNS754Y4R45QWE336QFX6ZR8DQGVQCULVZTV20TFVEYDMFQC")
                .expect("Invalid OhttpKeys");
        let arbitrary_url = Url::parse("https://example.com").unwrap();
        let uri = Receiver {
            context: SessionContext {
                address,
                directory: arbitrary_url.clone(),
                subdirectory: None,
                ohttp_keys,
                ohttp_relay: arbitrary_url.clone(),
                expiry: SystemTime::now() + Duration::from_secs(60),
                s: receiver_keys,
                e: None,
            },
            state: InitialState,
        }
        .pj_uri();
        assert_ne!(uri.extras.endpoint, arbitrary_url);
        assert!(!uri.extras.disable_output_substitution);
    }
}
