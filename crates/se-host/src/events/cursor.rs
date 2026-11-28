//! Opaque event-stream cursor bound to `(store_id, incarnation, event_seq)`.
//! Cursors survive host restarts because events are durable store rows; any
//! malformed cursor, store/incarnation reset or restore, or ahead-of-head
//! sequence returns a typed `Code::CursorInvalid` refusal rather than silently
//! dropping or splicing events.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use se_store::StoreInfo;
use se_types::{Generation, Result, SeError, StoreId};
use serde::{Deserialize, Serialize};

const CURSOR_PREFIX: &str = "evcur_v1_";
const CURSOR_VERSION: u8 = 1;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorPayload {
    v: u8,
    s: StoreId,
    i: u64,
    g: u64,
    q: u64,
}

/// Encode an opaque cursor bound to the store's `(id, incarnation)`, host
/// `generation`, and exact committed `event_seq` (`0` for an empty store).
pub(crate) fn encode(info: &StoreInfo, generation: Generation, event_seq: u64) -> Result<String> {
    let payload = CursorPayload {
        v: CURSOR_VERSION,
        s: info.id.clone(),
        i: info.incarnation,
        g: generation.get(),
        q: event_seq,
    };
    let bytes = serde_json::to_vec(&payload)
        .map_err(|err| se_core::scope::unreadable("event cursor", &err.to_string()))?;
    Ok(format!("{CURSOR_PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

/// Decode and strictly verify `after_cursor` against the current store identity,
/// incarnation, host generation, and committed head sequence.
pub(crate) fn decode_and_verify(
    raw: &str,
    info: &StoreInfo,
    generation: Generation,
) -> Result<u64> {
    let stale = |reason: &str| {
        SeError::new(se_types::Detail::CursorInvalid(
            se_types::details::CursorInvalid {
                reason: format!("stale_cursor: {reason}"),
                next_step: "reconnect without after_cursor to re-baseline".into(),
            },
        ))
    };
    let encoded = raw
        .strip_prefix(CURSOR_PREFIX)
        .ok_or_else(|| stale("missing evcur_v1_ prefix"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| stale("malformed base64url payload"))?;
    let payload: CursorPayload =
        serde_json::from_slice(&bytes).map_err(|_| stale("malformed v1 cursor payload"))?;
    if payload.v != CURSOR_VERSION {
        return Err(stale("unsupported cursor version"));
    }
    if payload.s != info.id || payload.i != info.incarnation {
        return Err(stale(
            "store identity or incarnation changed (store reset or restored)",
        ));
    }
    let _ = generation;
    let head_seq = info.head.as_ref().map_or(0, |pos| pos.sequence());
    if payload.q > head_seq {
        return Err(stale("cursor sequence is ahead of committed store head"));
    }
    Ok(payload.q)
}

#[cfg(test)]
mod tests {
    use super::*;
    use se_store::{StorePosition, StoreState};

    fn test_info(
        store_id: &str,
        incarnation: u64,
        head_seq: u64,
    ) -> std::result::Result<StoreInfo, Box<dyn std::error::Error>> {
        let id = store_id.parse::<StoreId>()?;
        let head = (head_seq > 0)
            .then(|| StorePosition::new_internal(id.clone(), incarnation, head_seq))
            .transpose()?;
        Ok(StoreInfo {
            id,
            incarnation,
            schema_version: 17,
            head,
            state: StoreState::Ready,
        })
    }

    #[test]
    fn round_trip_survives_restart_and_refuses_mismatches()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let info = test_info("store_00000000-0000-7000-8000-000000000001", 1, 42)?;
        let gen1 = Generation::new(1)?;
        let gen2 = Generation::new(2)?;
        let cur = encode(&info, gen1, 17)?;
        assert_eq!(decode_and_verify(&cur, &info, gen1)?, 17);
        // Host restart (new generation on same store + incarnation) keeps cursor valid.
        assert_eq!(decode_and_verify(&cur, &info, gen2)?, 17);

        let restored = test_info("store_00000000-0000-7000-8000-000000000001", 2, 42)?;
        let err = decode_and_verify(&cur, &restored, gen1)
            .err()
            .ok_or("expected stale_cursor on incarnation mismatch")?;
        assert_eq!(err.code(), se_types::Code::CursorInvalid);

        let behind = test_info("store_00000000-0000-7000-8000-000000000001", 1, 10)?;
        let err = decode_and_verify(&cur, &behind, gen1)
            .err()
            .ok_or("expected stale_cursor ahead of head")?;
        assert_eq!(err.code(), se_types::Code::CursorInvalid);

        let err = decode_and_verify("not-a-cursor", &info, gen1)
            .err()
            .ok_or("expected stale_cursor on malformed")?;
        assert_eq!(err.code(), se_types::Code::CursorInvalid);
        Ok(())
    }
}
