//! Windows provider streams: safe declarations over the host's existing IOCP.
use crate::{
    GenerationId, HostInstanceId, LifecycleId, NativeFailure, OwnedProcess, ProcError, ProcResult,
    ProcessRuntime, StandardIo,
};
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
/// A revocable arena reference, never a raw handle or an independent native owner.
pub struct StdioPort {
    pub(crate) _private: (),
}
pub struct ProviderStdio {
    /// Move into LaunchSpec; no parent copies of these child endpoints survive launch.
    pub child: StandardIo,
    pub port: StdioPort,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StdioReadStream {
    Stdout,
    Stderr,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StdioOperationId(pub u64);
/// References can be recovered from stdio_state after a future is dropped.
#[non_exhaustive]
pub struct StdioTicket {
    pub operation: StdioOperationId,
    pub identity: StdioIdentity,
}
pub struct StdioState {
    pub port: StdioPort,
    pub operations: Vec<StdioTicket>,
    pub stdin_closed: bool,
    pub binding: StdioBinding,
}
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
    pub(crate) _private: (),
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
/// Bounded native steps only. Future/caller drop never frees kernel-owned buffers.
pub trait ProviderStdioApi: ProcessRuntime {
    fn create_stdio(&self, owner: &OwnedProcess, config: StdioConfig) -> ProcResult<ProviderStdio>;
    /// Rebind an existing/recovered/staged port; creates no pipe and starts no I/O.
    fn attach_stdio(&self, owner: &OwnedProcess, config: StdioConfig) -> ProcResult<StdioState>;
    fn stdio_state(&self, owner: &OwnedProcess) -> ProcResult<Option<StdioState>>;
    fn begin_read(
        &self,
        port: &StdioPort,
        stream: StdioReadStream,
        max_bytes: u32,
    ) -> ProcResult<StdioTicket>;
    fn begin_write(
        &self,
        port: &StdioPort,
        bytes: Vec<u8>,
    ) -> Result<StdioTicket, StdioWriteRejection>;
    fn cancel(&self, ticket: &StdioTicket) -> ProcResult<StdioCancel>;
    /// Pending retains custody; each terminal result can be taken exactly once.
    fn take_completion(&self, ticket: &StdioTicket) -> ProcResult<StdioCompletion>;
    fn begin_close(&self, port: &StdioPort, scope: StdioCloseScope) -> ProcResult<StdioTicket>;
    /// Refuses until the terminal result has been taken and kernel use has ended.
    fn release_operation(&self, ticket: &StdioTicket) -> ProcResult<()>;
    fn release_stdio(&self, port: &StdioPort, witness: &StdioClosed) -> ProcResult<()>;
}
