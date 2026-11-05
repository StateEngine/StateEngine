//! Committed project records become rebuildable metadata and contentless tokens.
mod feed;
mod mentions;
pub use feed::{FeedReceipt, apply};
