use nostr::event::{EventBuilder, Kind, Tag};
use nostr::filter::SingleLetterTag;
use nostr::key::Keys;
use nostr::message::ClientMessage;
use nostr::util::{hex, JsonUtil};

use super::Error;

#[derive(Clone)]
pub(crate) struct Db {}

impl Db {
    pub(crate) fn new() -> Self { Self {} }

    pub(crate) async fn push_v2_nostr_payload(
        &self,
        mailbox_id: &payjoin::directory::ShortId,
        data: Vec<u8>,
    ) -> Result<(), NostrBackendError> {
        let hex_data = hex::encode(data);
        let hex_mailbox_id = hex::encode(mailbox_id.as_bytes());
        let ephemeral_key = Keys::generate();
        let ephemeral_pubkey = ephemeral_key.public_key();

        let event = EventBuilder::new(Kind::GiftWrap, hex_data)
            .tag(Tag::custom(
                nostr::event::TagKind::SingleLetter(SingleLetterTag::from_char('h').unwrap()),
                hex_mailbox_id.chars().map(|c| c.to_string()),
            ))
            .build(ephemeral_pubkey)
            .sign(&ephemeral_key)
            .await
            .unwrap();

        let json = ClientMessage::event(event).as_json();
        println!("{}", json);

        Ok(())
    }
}

impl super::Db for Db {
    type OperationalError = NostrBackendError;

    async fn post_v2_payload(
        &self,
        mailbox_id: &payjoin::directory::ShortId,
        data: Vec<u8>,
    ) -> Result<(), Error<Self::OperationalError>> {
        self.push_v2_nostr_payload(mailbox_id, data).await?;
        Ok(())
    }

    async fn wait_for_v2_payload(
        &self,
        mailbox_id: &payjoin::directory::ShortId,
    ) -> Result<Vec<u8>, Error<Self::OperationalError>> {
        unimplemented!()
    }

    async fn post_v1_response(
        &self,
        _mailbox_id: &payjoin::directory::ShortId,
        _data: Vec<u8>,
    ) -> Result<(), Error<Self::OperationalError>> {
        unimplemented!()
    }

    async fn post_v1_request_and_wait_for_response(
        &self,
        _mailbox_id: &payjoin::directory::ShortId,
        _data: Vec<u8>,
    ) -> Result<Vec<u8>, Error<Self::OperationalError>> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub(crate) enum NostrBackendError {}

impl crate::db::SendableError for NostrBackendError {}

impl std::error::Error for NostrBackendError {}

impl std::fmt::Display for NostrBackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { todo!() }
}
