use bitcoincore_rpc::jsonrpc::serde_json;
use payjoin::receive::v2::ActiveSession;
use payjoin::send::RequestContext;
use sled::IVec;
use url::Url;

use super::*;

impl Database {
    pub(crate) fn insert_recv_session(&self, session: ActiveSession) -> Result<()> {
        let key = &session.public_key().serialize();
        let value = serde_json::to_string(&session).map_err(Error::Serialize)?;
        self.0.insert(key.as_slice(), IVec::from(value.as_str()))?;
        self.0.flush()?;
        Ok(())
    }

    pub(crate) fn get_recv_session(&self) -> Result<Option<ActiveSession>> {
        if let Some(ivec) = self.0.get("recv_sessions")? {
            let session: ActiveSession =
                serde_json::from_slice(&ivec).map_err(Error::Deserialize)?;
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn clear_recv_session(&self) -> Result<()> {
        self.0.remove("recv_sessions")?;
        self.0.flush()?;
        Ok(())
    }

    pub(crate) fn insert_send_session(
        &self,
        session: &mut RequestContext,
        pj_url: &Url,
    ) -> Result<()> {
        let value = serde_json::to_string(session).map_err(Error::Serialize)?;
        self.0.insert(pj_url.to_string(), IVec::from(value.as_str()))?;
        self.0.flush()?;
        Ok(())
    }

    pub(crate) fn get_send_session(&self, pj_url: &Url) -> Result<Option<RequestContext>> {
        if let Some(ivec) = self.0.get(pj_url.to_string())? {
            let session: RequestContext =
                serde_json::from_slice(&ivec).map_err(Error::Deserialize)?;
            Ok(Some(session))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn clear_send_session(&self, pj_url: &Url) -> Result<()> {
        self.0.remove(pj_url.to_string())?;
        self.0.flush()?;
        Ok(())
    }
}
