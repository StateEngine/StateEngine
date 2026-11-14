use crate::CommitDurability;
use std::time::Duration;
/// Diagnostics separate from immutable receipts. commit_sync measures SQLite's
/// COMMIT call, not a claimed filesystem syscall duration/count.
#[derive(Clone, Debug)]
pub struct WriteTimings {
    pub request_key: Option<se_types::IdempotencyKey>,
    pub queue: Duration,
    pub transaction: Duration,
    pub commit_sync: Duration,
    pub checkpoint: Option<Duration>,
    pub group_requests: usize,
    /// The current outer transaction's measured synchronous setting, including
    /// promotion by another request. A replay receipt retains its original stamp.
    pub durability: CommitDurability,
}
