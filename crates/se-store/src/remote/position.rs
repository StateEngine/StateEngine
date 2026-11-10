//! Private replay positions carried only inside an authenticated encrypted cursor.
use super::*;
const LENGTH: usize = 33;
/// Fixed, versioned plaintext for the host cursor cipher. Never send or log these
/// bytes: they contain private store ordering. Bind grant, target, revision and
/// cursor purpose as cipher associated data before exposing the encrypted cursor.
pub fn position_payload(position: &StorePosition) -> StoreResult<[u8; LENGTH]> {
    let (store, incarnation, sequence) = position.storage_parts();
    if incarnation == 0 || sequence > i64::MAX as u64 {
        return Err(invalid("remote position range"));
    }
    let id = store
        .canonical_bytes()
        .map_err(invalid)?
        .ok_or_else(|| invalid("remote position requires canonical store identity"))?;
    let mut payload = [0; LENGTH];
    payload[0] = 1;
    payload[1..17].copy_from_slice(&id);
    payload[17..25].copy_from_slice(&incarnation.to_be_bytes());
    payload[25..].copy_from_slice(&sequence.to_be_bytes());
    Ok(payload)
}
/// Call only after authenticated opening and verification of cursor scope/purpose.
/// This reconstructs an opaque token, not admission: `remote_changes` independently
/// rejects a different store/incarnation or a position beyond its pinned snapshot.
pub fn position_from_payload(payload: &[u8]) -> StoreResult<StorePosition> {
    if payload.len() != LENGTH || payload[0] != 1 {
        return Err(invalid("remote position payload length or version"));
    }
    let store =
        StoreId::from_bytes(payload[1..17].try_into().map_err(invalid)?).map_err(invalid)?;
    let incarnation = u64::from_be_bytes(payload[17..25].try_into().map_err(invalid)?);
    let sequence = u64::from_be_bytes(payload[25..].try_into().map_err(invalid)?);
    if incarnation == 0 || sequence > i64::MAX as u64 {
        return Err(invalid("remote position range"));
    }
    StorePosition::new_internal(store, incarnation, sequence)
}
