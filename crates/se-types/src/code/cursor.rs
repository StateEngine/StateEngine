//! Domain-bound live keysets. Cursors carry positions, never authority or a BFS frontier.
use super::*;
type AtlasResult<T> = crate::Result<T>;
use crate::{Detail, SeError, details};
use serde::Serialize;
use sha2::Digest;

#[derive(Clone, Debug, Default, Eq, PartialEq, Ord, PartialOrd)]
pub struct CursorKey {
    pub integers: Vec<u64>,
    pub bytes: Vec<u8>,
}
impl CursorKey {
    fn validate(&self) -> AtlasResult<()> {
        if self.integers.len() > 8 || self.bytes.len() > 512 {
            return Err(cursor_invalid("oversized ordering key"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug)]
pub struct RankingClock {
    pub now_unix_ms: Option<i64>,
}
#[derive(Clone, Debug)]
pub struct TextWindow {
    pub last_touch_unix_ms: i64,
    pub file: [u8; 16],
    pub has_more: bool,
}
#[derive(Clone, Debug)]
pub struct CodeCursorPosition {
    mode: String,
    project: crate::ProjectId,
    root: RootId,
    epoch: CacheEpoch,
    query_digest: [u8; 32],
    pub last_key: CursorKey,
    pub generation_hint: Generation,
    pub change_fence: Option<Generation>,
    /// Freeze time decay across pages, including an explicitly unknown clock.
    pub ranking_clock: Option<RankingClock>,
    pub text_window: Option<TextWindow>,
}
#[path = "cursor/compact.rs"]
mod compact;
impl CodeCursorPosition {
    pub fn new(
        index: &IndexSummary,
        mode: &str,
        query_digest: [u8; 32],
        last_key: CursorKey,
        change_fence: Option<Generation>,
    ) -> AtlasResult<Self> {
        last_key.validate()?;
        if mode.is_empty() || mode.len() > 32 {
            return Err(cursor_invalid("invalid query mode"));
        }
        Ok(Self {
            mode: mode.into(),
            project: index.project.clone(),
            root: index.root.clone(),
            epoch: index
                .epoch
                .clone()
                .ok_or_else(|| cursor_invalid("index has no epoch"))?,
            query_digest,
            last_key,
            generation_hint: index
                .generation
                .ok_or_else(|| cursor_invalid("index has no generation"))?,
            change_fence,
            ranking_clock: None,
            text_window: None,
        })
    }
    pub fn with_ranking_time(mut self, now_unix_ms: Option<i64>) -> Self {
        self.ranking_clock = Some(RankingClock { now_unix_ms });
        self
    }
    pub fn with_text_window(mut self, window: Option<TextWindow>) -> Self {
        self.text_window = window;
        self
    }
    pub fn ranking_time(&self) -> AtlasResult<Option<i64>> {
        self.ranking_clock
            .as_ref()
            .map(|clock| clock.now_unix_ms)
            .ok_or_else(|| cursor_invalid("ranking clock absent: restart this search"))
    }
    pub fn resume_fence(
        &self,
        project: &crate::ProjectId,
        root: &RootId,
        epoch: &CacheEpoch,
        viewer: &AtlasPrincipal,
    ) -> AtlasResult<u64> {
        if &self.project != project
            || &self.root != root
            || &self.epoch != epoch
            || self.mode != "changes-range"
            || self.query_digest != cursor_digest(&("changes-range", viewer))?
            || self.last_key.integers.len() != 2
            || self.last_key.integers[1] != u64::from(u32::MAX)
            || !self.last_key.bytes.is_empty()
            || self.change_fence.is_some()
            || self.last_key.integers[0] > self.generation_hint.0
        {
            return Err(cursor_invalid(
                "resume cursor domain/fence differs from its delivered offer",
            ));
        }
        Ok(self.last_key.integers[0])
    }
    pub fn encode(&self) -> AtlasResult<AtlasCursor> {
        self.last_key.validate()?;
        let bytes = compact::encode(self)?;
        if bytes.len() > 3072 {
            return Err(cursor_invalid("decoded cursor exceeds 3072 bytes"));
        }
        AtlasCursor::new(encode(&bytes))
    }
    pub fn decode(value: &AtlasCursor) -> AtlasResult<Self> {
        use super::AtlasText;
        let bytes = decode(value.as_str())?;
        if bytes.first() != Some(&2) {
            return Err(cursor_invalid(
                "this page link has expired, run the search again",
            ));
        }
        let cursor = compact::decode(&bytes)?;
        if compact::encode(&cursor)? != bytes {
            return Err(cursor_invalid("noncanonical compact cursor"));
        }
        cursor.last_key.validate()?;
        Ok(cursor)
    }
    pub fn validate(
        &self,
        index: &IndexSummary,
        mode: &str,
        query_digest: [u8; 32],
    ) -> AtlasResult<bool> {
        if self.project != index.project || self.root != index.root {
            return Err(cursor_invalid(
                "cursor project/root differs from the bound reader",
            ));
        }
        if Some(&self.epoch) != index.epoch.as_ref() {
            return Err(cursor_invalid(
                "CursorEpochMismatch: restart against the current epoch",
            ));
        }
        if self.mode != mode || self.query_digest != query_digest {
            return Err(cursor_invalid(
                "CursorQueryMismatch: use the original selector, filters and viewer",
            ));
        }
        let current = index
            .generation
            .ok_or_else(|| cursor_invalid("index has no generation"))?;
        if self.generation_hint.0 > current.0
            || self.change_fence.is_some_and(|fence| fence.0 > current.0)
        {
            return Err(cursor_invalid("cursor generation is beyond this index"));
        }
        Ok(self.generation_hint != current)
    }
}
pub fn cursor_digest(value: &impl Serialize) -> AtlasResult<[u8; 32]> {
    Ok(sha2::Sha256::digest(serde_json::to_vec(value).map_err(cursor_invalid)?).into())
}
pub fn cursor_invalid(reason: impl std::fmt::Display) -> SeError {
    SeError::new(Detail::CursorInvalid(details::CursorInvalid {
        reason: reason.to_string(),
        next_step:"Restart the Atlas read without this cursor, or use a cursor returned for the same viewer, root and query.".into(),
    }))
}
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
fn encode(bytes: &[u8]) -> String {
    let mut result = String::with_capacity((bytes.len() * 4).div_ceil(3));
    for chunk in bytes.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for shift in [18, 12, 6, 0].into_iter().take(chunk.len() + 1) {
            result.push(ALPHABET[((bits >> shift) & 63) as usize] as char);
        }
    }
    result
}
fn decode(text: &str) -> AtlasResult<Vec<u8>> {
    if text.is_empty() || text.len() > 4096 || text.len() % 4 == 1 {
        return Err(cursor_invalid("invalid base64url length"));
    }
    let mut result = Vec::with_capacity(text.len() * 3 / 4);
    let mut bits = 0u32;
    let mut count = 0u8;
    for byte in text.bytes() {
        let value = ALPHABET
            .iter()
            .position(|v| *v == byte)
            .ok_or_else(|| cursor_invalid("invalid base64url character"))?
            as u32;
        bits = (bits << 6) | value;
        count += 6;
        if count >= 8 {
            count -= 8;
            result.push((bits >> count) as u8);
        }
    }
    if result.len() > 3072 || encode(&result) != text {
        return Err(cursor_invalid("noncanonical base64url"));
    }
    Ok(result)
}
