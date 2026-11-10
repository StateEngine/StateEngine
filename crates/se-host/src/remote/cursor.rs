//! Encrypted, purpose-separated cursors. Private floor positions never enter JSON.
use super::*;
use se_core::store_error::store_error;
use se_types::{Cursor, SeError};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub(crate) struct Cursors {
    cipher: Arc<keys::CursorCipher>,
    host: RemoteHostId,
    store: se_store::StoreInfo,
}
impl Cursors {
    pub fn new(
        cipher: Arc<keys::CursorCipher>,
        host: RemoteHostId,
        store: se_store::StoreInfo,
    ) -> Self {
        Self {
            cipher,
            host,
            store,
        }
    }
    fn associated(
        &self,
        request: &view_request::ViewRequest,
        target: Option<&RemoteTarget>,
        purpose: &str,
    ) -> Result<Vec<u8>> {
        let mut selected = request.targets().to_vec();
        selected.sort();
        let filter = serde_json::to_vec(&selected).map_err(|_| invalid())?;
        let filter: [u8; 32] = Sha256::digest(filter).into();
        let mut associated = serde_json::json!({"schema":"stateengine.remote-cursor/v1","host":self.host,"store":self.store.id,"incarnation":self.store.incarnation,"target":target,"filter":filter,"purpose":purpose});
        request.cursor_authority(&mut associated);
        serde_json::to_vec(&associated).map_err(|_| invalid())
    }
    pub fn seal(
        &self,
        request: &view_request::ViewRequest,
        target: Option<&RemoteTarget>,
        purpose: &str,
        payload: &[u8],
    ) -> Result<Cursor> {
        self.sealed_receipt(payload, &self.associated(request, target, purpose)?)
    }
    pub fn sealed_receipt(&self, payload: &[u8], associated: &[u8]) -> Result<Cursor> {
        let envelope = self.cipher.seal(payload, associated)?;
        let mut text = String::with_capacity(4 + 2 * envelope.len());
        text.push_str("rc1.");
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in envelope {
            text.push(HEX[(byte >> 4) as usize] as char);
            text.push(HEX[(byte & 15) as usize] as char);
        }
        Cursor::new(text)
    }
    pub fn open(
        &self,
        request: &view_request::ViewRequest,
        target: Option<&RemoteTarget>,
        purpose: &str,
        cursor: &Cursor,
    ) -> Result<Vec<u8>> {
        let text = cursor.as_str().strip_prefix("rc1.").ok_or_else(invalid)?;
        if text.len() % 2 != 0 || text.len() > 4092 {
            return Err(invalid());
        }
        fn nibble(byte: u8) -> Result<u8> {
            match byte {
                b'0'..=b'9' => Ok(byte - b'0'),
                b'a'..=b'f' => Ok(byte - b'a' + 10),
                _ => Err(invalid()),
            }
        }
        let envelope = text
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| Ok(nibble(pair[0])? * 16 + nibble(pair[1])?))
            .collect::<Result<Vec<_>>>()?;
        self.cipher
            .open(&envelope, &self.associated(request, target, purpose)?)
    }
    pub fn json<T: Serialize>(
        &self,
        request: &view_request::ViewRequest,
        target: Option<&RemoteTarget>,
        purpose: &str,
        value: &T,
    ) -> Result<Cursor> {
        self.seal(
            request,
            target,
            purpose,
            &serde_json::to_vec(value).map_err(|_| invalid())?,
        )
    }
    pub fn decoded<T: DeserializeOwned>(
        &self,
        request: &view_request::ViewRequest,
        target: Option<&RemoteTarget>,
        purpose: &str,
        cursor: &Cursor,
    ) -> Result<T> {
        serde_json::from_slice(&self.open(request, target, purpose, cursor)?).map_err(|_| invalid())
    }
    pub fn durable(
        &self,
        request: &view_request::ViewRequest,
        target: &RemoteTarget,
        position: &se_store::StorePosition,
    ) -> Result<Cursor> {
        self.seal(
            request,
            Some(target),
            "durable",
            &se_store::remote::position_payload(position).map_err(|e| store_error(&e))?,
        )
    }
    pub fn position(
        &self,
        request: &view_request::ViewRequest,
        target: &RemoteTarget,
        cursor: &Cursor,
    ) -> Result<se_store::StorePosition> {
        se_store::remote::position_from_payload(&self.open(
            request,
            Some(target),
            "durable",
            cursor,
        )?)
        .map_err(|e| store_error(&e))
    }
}
fn invalid() -> SeError {
    SeError::new(se_types::Detail::CursorInvalid(se_types::details::CursorInvalid {reason:"encrypted cursor binding, encoding or purpose differs".into(),next_step:"Reset only this scoped view and retain the key-loss or restore diagnostic; never use an unsigned cursor.".into()}))
}
