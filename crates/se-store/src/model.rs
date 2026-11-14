use crate::*;
/// Trusted maintenance input, not a public operation or cross-scope admission.
/// Owner is one registry runtime.owner; session is the witnessed project binding.
pub struct FirstBinding {
    pub owner: crate::AtomicBatch,
    pub session: crate::AtomicBatch,
}
/// Two scoped operation receipts from the same successful outer FULL commit.
pub struct FirstBindingReceipt {
    pub owner: CommitReceipt,
    pub session: CommitReceipt,
}
/// Store-owned shared backup/WAL coordination; no public constructor or mutator.
/// Private implementation retains store/incarnation/generation and pin/cancel state.
#[derive(Clone)]
pub struct BackupContext {
    pub(crate) state: std::sync::Arc<crate::backup_context::State>,
}
