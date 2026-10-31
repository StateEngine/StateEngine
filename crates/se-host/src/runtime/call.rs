//! Owned handoff to the planner/commit/continuation executor. Native admission
//! precedes construction; no snapshot or SQL handle is carried across an await.
use super::BlockingPool;
use crate::client::lease::Deadline;
use se_core::{
    admission::HumanTerminal,
    dispatch::Kernel,
    ops::{AnyOp, CliSelections},
};
use se_store::{Admission, SqliteClient, SqliteReader};
use std::sync::Arc;

pub enum HostedInput {
    Operation(AnyOp),
    Capture(Box<TrustedCapture>),
}
/// Only the host's pinned-source consumer constructs this input; there is no
/// wire Deserialize or public tool argument that can supply its trusted facts.
pub struct TrustedCapture {
    pub request: se_core::ops::hook::CaptureRequest,
    pub facts: se_core::ops::hook::CaptureFacts,
}
pub struct HostedCall {
    pub input: HostedInput,
    pub kernel: Kernel,
    pub admission: Admission,
    pub terminal: HumanTerminal,
    /// Decoded once by the core DTO. Its project is bound before any snapshot;
    /// remaining selectors are applied in the planning snapshot itself.
    pub selections: Option<CliSelections>,
}
#[derive(Clone)]
pub struct ExecutionContext {
    pub reader: Arc<SqliteReader>,
    pub writer: SqliteClient,
    pub blocking: BlockingPool,
    pub generation: se_types::Generation,
}
pub struct ExecutionCall {
    pub admitted: HostedCall,
    pub deadline: Deadline,
}

/// One request's executor result. Timings are moved out of its own awaited
/// store completion before the receipt is consumed by the core continuation.
/// Read-only and unmeasured completions carry None; never consult an aggregate.
pub struct ExecutedCall {
    pub output: se_core::ops::AnyOutput,
    pub write_timings: Option<se_store::WriteTimings>,
}
