//! The Atlas v5 service the host runs: one single-writer engine per
//! registered worktree, a native watcher feeding a bounded dirty set, and
//! queries that overlay that set so an edit is visible before its batch
//! commits. Answers are mapped onto the shared `se_types::code` wire.
//!
//! Every source byte is read through `se_atlas_index` custody; nothing here
//! opens a source file by an OS path. Each root's writer runs on its own
//! thread; queries open read-only connections and never write.
#![forbid(unsafe_code)]

mod dirty;
mod engine;
mod error;
mod filter;
mod githead;
mod ignores;
mod overlay;
mod read;
mod reconcile;
mod records;
mod root;
mod settle;
mod watch;
mod wire;

pub use dirty::{Change, DirtySet, MAX_DIRTY};
pub use engine::{DEBOUNCE, MAX_DEBOUNCE};
pub use filter::{Reported, classify};
pub use overlay::{MAX_OVERLAY_BYTES, MAX_STAT_FILES};
pub use read::{HookOutline, HookSymbol, RecordCheck, STARTING};
pub use root::{FeedReceipt, Root, RootSpec};
pub use settle::{Phase, Progress, Watch};
pub use wire::history::retrieval as resume_retrieval;
