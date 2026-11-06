//! Small opaque continuation bound to this host/store/Owner and exact filter.
use super::*;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cursor {
    pub connections: u64,
    pub mail: u64,
    pub incarnation: u64,
    pub head: u64,
    pub health: u64,
}
fn mac(
    key: &se_types::Secret,
    store: &se_types::StoreId,
    owner: &se_types::HumanId,
    filter: &Option<ChannelId>,
    receipt: &Option<ReceiptId>,
    bytes: &[u8],
) -> Result<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.expose())
        .map_err(|_| channel_error(ChannelError::CredentialStoreUnavailable))?;
    mac.update(b"StateEngine channel inspect cursor v1\0");
    let binding = serde_json::to_vec(&(store, owner, filter, receipt))
        .map_err(|_| channel_error(ChannelError::InvalidInput))?;
    mac.update(&binding);
    mac.update(bytes);
    Ok(mac)
}
pub(super) fn encode(
    key: &se_types::Secret,
    store: &se_types::StoreId,
    owner: &se_types::HumanId,
    filter: &Option<ChannelId>,
    receipt: &Option<ReceiptId>,
    cursor: &Cursor,
) -> Result<String> {
    let bytes =
        serde_json::to_vec(cursor).map_err(|_| channel_error(ChannelError::InvalidInput))?;
    let signature = mac(key, store, owner, filter, receipt, &bytes)?
        .finalize()
        .into_bytes();
    let value = format!(
        "cc1.{}.{}",
        se_types::hex_lower(&bytes),
        se_types::hex_lower(&signature)
    );
    if value.len() > 512 {
        return Err(channel_error(ChannelError::InvalidInput));
    }
    Ok(value)
}
fn hex(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(channel_error(ChannelError::InvalidInput));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            std::str::from_utf8(chunk)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .ok_or_else(|| channel_error(ChannelError::InvalidInput))
        })
        .collect()
}
impl Channels {
    pub(super) fn decode_cursor(
        &self,
        value: &str,
        filter: &Option<ChannelId>,
        receipt: &Option<ReceiptId>,
    ) -> Result<Cursor> {
        if value.len() > 512 {
            return Err(channel_error(ChannelError::InvalidInput));
        }
        let mut parts = value.split('.');
        if parts.next() != Some("cc1") {
            return Err(channel_error(ChannelError::InvalidInput));
        }
        let bytes = hex(parts
            .next()
            .ok_or_else(|| channel_error(ChannelError::InvalidInput))?)?;
        let signature = hex(parts
            .next()
            .ok_or_else(|| channel_error(ChannelError::InvalidInput))?)?;
        if parts.next().is_some() {
            return Err(channel_error(ChannelError::InvalidInput));
        }
        mac(
            &self.pairing_key,
            &self.store_id,
            &self.owner,
            filter,
            receipt,
            &bytes,
        )?
        .verify_slice(&signature)
        .map_err(|_| channel_error(ChannelError::InvalidInput))?;
        let cursor: Cursor = serde_json::from_slice(&bytes)
            .map_err(|_| channel_error(ChannelError::InvalidInput))?;
        if cursor.incarnation == 0
            || [cursor.head, cursor.connections, cursor.mail]
                .iter()
                .any(|v| *v > i64::MAX as u64)
        {
            return Err(channel_error(ChannelError::InvalidInput));
        }
        Ok(cursor)
    }
}
