//! Windows provider stream arena handles and trait.
use crate::{
    OwnedProcess, ProcResult, ProcessRuntime, StandardIo, StdioBinding, StdioCancel,
    StdioCloseScope, StdioClosed, StdioCompletion, StdioConfig, StdioIdentity, StdioOperationId,
    StdioReadStream, StdioWriteRejection,
};

/// A revocable arena reference, never a raw handle or an independent native owner.
pub struct StdioPort {
    pub(crate) key: crate::runtime::Reference,
    pub(crate) binding: u64,
}
pub struct ProviderStdio {
    /// Move into LaunchSpec; no parent copies of these child endpoints survive launch.
    pub child: StandardIo,
    pub port: StdioPort,
}
/// References can be recovered from stdio_state after a future is dropped.
#[non_exhaustive]
pub struct StdioTicket {
    pub operation: StdioOperationId,
    pub identity: StdioIdentity,
    pub(crate) key: crate::runtime::Reference,
    pub(crate) binding: u64,
}
pub struct StdioState {
    pub port: StdioPort,
    pub operations: Vec<StdioTicket>,
    pub stdin_closed: bool,
    pub binding: StdioBinding,
}

/// Bounded native steps only. Future/caller drop never frees kernel-owned buffers.
pub trait ProviderStdioApi: ProcessRuntime {
    /// Metadata of the retained lifecycle, including a prepared scope before
    /// a root is published. A native implementation must fence the reference.
    fn stdio_identity(&self, owner: &OwnedProcess) -> ProcResult<StdioIdentity> {
        let record = self.describe(owner)?;
        Ok(StdioIdentity {
            lifecycle: record.lifecycle,
            host: record.host,
            generation: record.generation,
        })
    }
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
