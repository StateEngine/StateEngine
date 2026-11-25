//! Windows provider streams: safe declarations over the host's existing IOCP.
use crate::{GenerationId, HostInstanceId, LifecycleId, NativeFailure, ProcError};
use std::sync::Arc;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdioIdentity {
    pub lifecycle: LifecycleId,
    pub host: HostInstanceId,
    pub generation: GenerationId,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StdioLimits {
    pub max_read_bytes: u32,
    pub max_write_bytes: u32,
    pub max_buffer_bytes: u32,
}
pub struct StdioConfig {
    pub identity: StdioIdentity,
    pub limits: StdioLimits,
    pub notifications: Arc<dyn StdioSink>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StdioReadStream {
    Stdout,
    Stderr,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StdioOperationId(pub u64);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StdioBinding {
    Unbound,
    Draining,
    Ready,
}
/// Deliberately no Debug/Clone: streams may carry provider credentials.
pub struct StdioWriteRejection {
    pub error: ProcError,
    pub bytes: Vec<u8>,
}
pub enum StdioOutcome {
    Complete,
    Cancelled,
    Failed(NativeFailure),
}
/// Terminal results retain partial bytes/count even on cancellation or failure.
pub enum StdioCompletion {
    Pending,
    Read {
        stream: StdioReadStream,
        bytes: Vec<u8>,
        /// True only with Complete for BROKEN_PIPE, PIPE_NOT_CONNECTED or HANDLE_EOF.
        eof: bool,
        outcome: StdioOutcome,
    },
    Write {
        bytes: Vec<u8>,
        written: u32,
        outcome: StdioOutcome,
    },
    Close {
        scope: StdioCloseScope,
        result: Result<StdioClosed, NativeFailure>,
    },
}
/// Neither a cancel acknowledgment nor an absent request proves completion.
pub enum StdioCancel {
    Requested,
    AlreadyCompleted,
    Failed(NativeFailure),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StdioCloseScope {
    /// Finish the accepted write before closing stdin; output reads stay active.
    Stdin,
    /// Cancel/drain all I/O and close all host endpoints.
    All,
}
/// Selected endpoints closed and their kernel requests drained; results need release.
/// release_stdio accepts only a matching All witness, never a Stdin witness.
pub struct StdioClosed {
    pub(crate) native: std::sync::Weak<crate::platform::NativeStdio>,
    pub(crate) identity: StdioIdentity,
    pub(crate) binding: u64,
    pub(crate) scope: StdioCloseScope,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StdioNotice {
    pub identity: StdioIdentity,
    pub kind: StdioNoticeKind,
    pub sequence: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StdioNoticeKind {
    Operation(StdioOperationId),
    BindingChanged,
}
/// Coalesced lock-free nudge only; notify is unwind-contained inside se-proc.
pub trait StdioSink: Send + Sync {
    fn notify(&self, notice: StdioNotice);
}
