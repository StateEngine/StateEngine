//! Recorded provider metadata shares the immutable capture log and its consent.
use crate::StoredEvent;
use se_types::Read;
pub const TRANSCRIPT_EVENT_PREFIX: &str = "se.notice.v1/";
pub struct TranscriptRecords {
    pub events: Vec<StoredEvent>,
    pub last_compaction: Read<StoredEvent>,
    pub omitted: u64,
}
