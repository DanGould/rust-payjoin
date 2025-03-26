use std::sync::Arc;

use bitcoincore_rpc::jsonrpc::serde_json;
use payjoin::directory::ShortId;
use payjoin::persist::Persister;
use payjoin::receive::v2::Receiver;
use payjoin::send::v2::Sender;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sled::{IVec, Tree};
use url::Url;

use super::*;

#[derive(Clone)]
pub(crate) struct RecieverPersister(pub Arc<Database>);
impl Persister for RecieverPersister {
    type Key = ShortId;
    type Error = crate::db::error::Error;
    fn save<T: Serialize>(
        &mut self,
        key: Self::Key,
        value: T,
    ) -> std::result::Result<(), Self::Error> {
        let recv_tree = self.0 .0.open_tree("recv_sessions")?;
        let value = serde_json::to_string(&value).map_err(Error::Serialize)?;
        recv_tree.insert(key.as_slice(), IVec::from(value.as_str()))?;
        recv_tree.flush()?;
        Ok(())
    }
    fn load<T: DeserializeOwned>(&self, key: Self::Key) -> std::result::Result<T, Self::Error> {
        let recv_tree = self.0 .0.open_tree("recv_sessions")?;
        let value = recv_tree.get(key.as_slice())?.ok_or(Error::NotFound(key.to_string()))?;
        let value = serde_json::from_slice(&value).map_err(Error::Deserialize)?;
        Ok(value)
    }
}

impl Database {
    pub(crate) fn get_recv_sessions(&self) -> Result<Vec<Receiver>> {
        let recv_tree = self.0.open_tree("recv_sessions")?;
        let mut sessions = Vec::new();
        for item in recv_tree.iter() {
            let (_, value) = item?;
            let session: Receiver = serde_json::from_slice(&value).map_err(Error::Deserialize)?;
            sessions.push(session);
        }
        Ok(sessions)
    }

    pub(crate) fn clear_recv_session(&self) -> Result<()> {
        let recv_tree: Tree = self.0.open_tree("recv_sessions")?;
        recv_tree.clear()?;
        recv_tree.flush()?;
        Ok(())
    }

    pub(crate) fn insert_send_session(&self, session: &mut Sender, pj_url: &Url) -> Result<()> {
        let send_tree: Tree = self.0.open_tree("send_sessions")?;
        let value = serde_json::to_string(session).map_err(Error::Serialize)?;
        send_tree.insert(pj_url.to_string(), IVec::from(value.as_str()))?;
        send_tree.flush()?;
        Ok(())
    }

    pub(crate) fn get_send_sessions(&self) -> Result<Vec<Sender>> {
        let send_tree: Tree = self.0.open_tree("send_sessions")?;
        let mut sessions = Vec::new();
        for item in send_tree.iter() {
            let (_, value) = item?;
            let session: Sender = serde_json::from_slice(&value).map_err(Error::Deserialize)?;
            sessions.push(session);
        }
        Ok(sessions)
    }

    pub(crate) fn get_send_session(&self, pj_url: &Url) -> Result<Option<Sender>> {
        let send_tree = self.0.open_tree("send_sessions")?;
        if let Some(val) = send_tree.get(pj_url.to_string())? {
            let session: Sender = serde_json::from_slice(&val).map_err(Error::Deserialize)?;
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn clear_send_session(&self, pj_url: &Url) -> Result<()> {
        let send_tree: Tree = self.0.open_tree("send_sessions")?;
        send_tree.remove(pj_url.to_string())?;
        send_tree.flush()?;
        Ok(())
    }
}
