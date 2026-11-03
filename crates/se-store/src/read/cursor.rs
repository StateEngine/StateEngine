use super::*;
use sha2::{Digest, Sha256};
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
fn encode(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..chunk.len() + 1 {
            out.push(ALPHABET[((bits >> (18 - i * 6)) & 63) as usize] as char);
        }
    }
    out
}
fn decode(text: &str) -> StoreResult<Vec<u8>> {
    if text.len() > 192 {
        return Err(fail(
            StoreErrorCode::CursorInvalid,
            "cursor exceeds 192 bytes",
        ));
    }
    let mut out = Vec::new();
    let mut bits = 0u32;
    let mut count = 0;
    for b in text.bytes() {
        let value = ALPHABET.iter().position(|v| *v == b).ok_or_else(|| {
            fail(
                StoreErrorCode::CursorInvalid,
                "cursor is not unpadded base64url",
            )
        })?;
        bits = (bits << 6) | value as u32;
        count += 6;
        if count >= 8 {
            count -= 8;
            out.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    if encode(&out) != text {
        return Err(fail(
            StoreErrorCode::CursorInvalid,
            "noncanonical cursor encoding",
        ));
    }
    Ok(out)
}
impl SqliteSnapshot {
    fn query_digest(&self, binding: &str) -> StoreResult<[u8; 32]> {
        let bytes = codec::encode(&(
            binding,
            &self.scope.admission.scope,
            &self.scope.admission.actor,
            format!("{:?}", self.scope.visibility),
        ))?;
        Ok(Sha256::digest(bytes.as_bytes()).into())
    }
    pub(super) fn cursor(&self, binding: &str, h: u64, after: u64) -> StoreResult<Cursor> {
        let mut bytes = vec![1, mode(binding)];
        bytes.extend(
            canonical(self.info.id.as_str())
                .ok_or_else(|| invalid("canonical StoreId required"))?,
        );
        bytes.extend(self.info.incarnation.to_be_bytes());
        bytes.extend(h.to_be_bytes());
        bytes.extend(after.to_be_bytes());
        bytes.extend(self.query_digest(binding)?);
        Cursor::new(encode(&bytes)).map_err(invalid)
    }
    pub(super) fn window(
        &self,
        budget: &ReadBudget,
        binding: &str,
        live: bool,
    ) -> StoreResult<(u64, u64)> {
        if budget.page.limit.get() > 1000
            || budget.page.max_bytes.get() > 2 * 1024 * 1024
            || budget.deadline.is_zero()
            || budget.deadline > std::time::Duration::from_secs(5)
        {
            return Err(fail(
                StoreErrorCode::ReadBudgetTooSmall,
                "read needs limit 1..1000, 1..2 MiB bytes and deadline up to 5 seconds",
            ));
        }
        let h = self
            .info
            .head
            .as_ref()
            .map(StorePosition::sequence)
            .unwrap_or(0);
        let Some(cursor) = &budget.page.after else {
            return Ok((h, 0));
        };
        let bytes = decode(cursor.as_str())?;
        if bytes.len() != 74 || bytes[0] != 1 || bytes[1] != mode(binding) {
            return Err(fail(
                StoreErrorCode::CursorInvalid,
                "cursor version/mode/length differs",
            ));
        }
        let number = |start: usize| -> StoreResult<u64> {
            Ok(u64::from_be_bytes(
                bytes[start..start + 8].try_into().map_err(invalid)?,
            ))
        };
        let store = canonical(self.info.id.as_str())
            .ok_or_else(|| invalid("canonical StoreId required"))?;
        if bytes[2..18] != store || number(18)? != self.info.incarnation {
            return Err(fail(
                StoreErrorCode::CursorStale,
                "cursor store/incarnation changed",
            ));
        }
        let prior = number(26)?;
        let last = number(34)?;
        if bytes[42..74] != self.query_digest(binding)? || last > prior || prior > h {
            return Err(fail(
                StoreErrorCode::CursorInvalid,
                "cursor principal/scope/query/window differs",
            ));
        }
        Ok((if live { h } else { prior }, last))
    }
}
/// Decode an end cursor without erasing malformed versus stale failures.
pub(crate) fn checked_window_end(text: &str, store: &[u8], incarnation: u64) -> StoreResult<u64> {
    let bytes = decode(text)?;
    if bytes.len() != 74 || bytes[0] != 1 || !matches!(bytes[1], 1..=3) {
        return Err(fail(
            StoreErrorCode::CursorInvalid,
            "cursor end version/mode/length differs",
        ));
    }
    if &bytes[2..18] != store
        || u64::from_be_bytes(bytes[18..26].try_into().map_err(invalid)?) != incarnation
    {
        return Err(fail(
            StoreErrorCode::CursorStale,
            "cursor end store/incarnation changed",
        ));
    }
    Ok(u64::from_be_bytes(
        bytes[34..42].try_into().map_err(invalid)?,
    ))
}
impl SqliteSnapshot {
    pub(super) fn position_binding(&self, purpose: PositionPurpose) -> StoreResult<String> {
        codec::encode(&(
            "position",
            &self.scope.admission.scope,
            &self.scope.admission.actor,
            match purpose {
                PositionPurpose::Receipt => "receipt".to_string(),
                PositionPurpose::Checked => "checked".to_string(),
                PositionPurpose::History => "history".to_string(),
                PositionPurpose::Continuity(agent) => format!("continuity:{}", agent.as_str()),
            },
        ))
    }
    pub(super) fn read_cursor_position(
        &self,
        cursor: &Cursor,
        purpose: PositionPurpose,
    ) -> StoreResult<StorePosition> {
        let binding = self.position_binding(purpose)?;
        let bytes = decode(cursor.as_str())?;
        if bytes.len() != 74 || bytes[0] != 1 || bytes[1] != mode(&binding) {
            return Err(fail(
                StoreErrorCode::CursorInvalid,
                "not a store position cursor",
            ));
        }
        let number = |start: usize| -> StoreResult<u64> {
            Ok(u64::from_be_bytes(
                bytes[start..start + 8].try_into().map_err(invalid)?,
            ))
        };
        let store = canonical(self.info.id.as_str())
            .ok_or_else(|| invalid("canonical StoreId required"))?;
        let head = self
            .info
            .head
            .as_ref()
            .map(StorePosition::sequence)
            .unwrap_or(0);
        let sequence = number(26)?;
        if bytes[2..18] != store || number(18)? != self.info.incarnation || sequence > head {
            return Err(fail(
                StoreErrorCode::CursorStale,
                "position cursor belongs to another store, incarnation or later snapshot",
            ));
        }
        if number(34)? != sequence || bytes[42..74] != self.query_digest(&binding)? {
            return Err(fail(
                StoreErrorCode::CursorInvalid,
                "position cursor principal/scope/purpose differs",
            ));
        }
        StorePosition::new_internal(self.info.id.clone(), self.info.incarnation, sequence)
    }
}
fn mode(binding: &str) -> u8 {
    if binding.starts_with("live:") {
        1
    } else if binding.starts_with("history:") {
        2
    } else {
        3
    }
}
