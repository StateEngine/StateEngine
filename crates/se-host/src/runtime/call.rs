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
    /// Exact active credential observed by native/session admission; never wire-selected.
    pub remote_credential: Option<(se_store::RecordId, [u8; 32])>,
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
    pub atlas: Arc<crate::atlas_runtime::read_port::AtlasOwnerPort>,
    pub(crate) mail_waits: Arc<crate::http::mail::Waits>,
    pub(crate) http_proofs: Arc<crate::http::proof::Challenges>,
    pub(crate) state_directory: std::path::PathBuf,
    pub reader: Arc<SqliteReader>,
    pub(crate) reads: se_store::ReadPhasePool,
    pub writer: SqliteClient,
    pub blocking: BlockingPool,
    pub generation: se_types::Generation,
    pub(crate) pending_writes: super::failure::PendingWrites,
    /// The native process coordinator, installed once before serving.
    pub(crate) custody: Arc<std::sync::OnceLock<Arc<dyn CustodyExecutor>>>,
    pub(crate) ownership_fault: Arc<super::tasks::OwnershipFault>,
}
/// The launch/stop/remove coordinator's entry: it resolves a core custody plan
/// (native effects plus their FULL commits) for one admitted caller. Installed
/// through `HostedRuntime::install_custody`; absent, custody plans refuse.
pub trait CustodyExecutor: Send + Sync {
    /// A failed native hook leaves its cursor with the existing session monitor.
    /// This wake supplies no transcript, capture authority or completion proof.
    fn notify_capture(&self, _session: &crate::SessionIdentity) -> se_types::Result<()> {
        Ok(())
    }
    /// Enrich retained provider coordinates with authenticated current reads,
    /// after the store read pin and native observation worker are released.
    fn observe_output<'a>(
        &'a self,
        output: se_core::ops::AnyOutput,
        _deadline: &'a Deadline,
    ) -> crate::HostFuture<'a, se_core::ops::AnyOutput> {
        Box::pin(async move { Ok(output) })
    }

    #[cfg(feature = "remote")]
    fn refresh_remote<'a>(&'a self, _deadline: &'a Deadline) -> crate::HostFuture<'a, ()> {
        Box::pin(async {
            Err(se_types::SeError::invalid(
                "remote publisher",
                "a native coordinator supporting attributed provider observations",
            ))
        })
    }

    /// One finite live-work sweep, under the host's original timer budget.
    fn catch_up<'a>(&'a self, _deadline: &'a Deadline) -> crate::HostFuture<'a, ()> {
        Box::pin(async {
            Err(se_core::scope::unreadable(
                "live-work catch-up",
                "the active custody coordinator must supply native and capture readback",
            ))
        })
    }
    /// Called by the retained completion observer only after an actual commit.
    /// This is an event hint, never admission, delivery or an inbox read.
    fn notify_mail(&self, _recipients: &[super::MailRecipient]) -> se_types::Result<()> {
        Ok(())
    }

    /// Import may adopt an old user model under the current owner's actual
    /// safe default. This port exposes no commands, credentials or old grants.
    fn import_profiles(&self) -> se_types::Result<Vec<se_store::Profile>> {
        Err(se_core::scope::unreadable(
            "import profile defaults",
            "the active process coordinator must supply its validated current-owner defaults",
        ))
    }
    fn execute<'a>(
        &'a self,
        plan: se_core::ports::CustodyPlan,
        admission: Admission,
        deadline: &'a Deadline,
    ) -> crate::HostFuture<'a, se_core::ops::AnyOutput>;
    /// Admission is fenced, but accepted calls have not joined yet. Durably
    /// request interruption of provider readiness without aborting accepted
    /// allocations, writes or active work. Final custody shutdown remains owed.
    fn begin_shutdown<'a>(&'a self, _deadline: &'a Deadline) -> crate::HostFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    /// At host shutdown, after request admission closed and before capture is
    /// fenced and storage drains: fence new launches, stop native lifecycles
    /// with their final capture, and join monitors. An incomplete report keeps
    /// the host's lease and writer.
    fn shutdown<'a>(&'a self, deadline: &'a Deadline) -> crate::HostFuture<'a, CustodyShutdown>;
}
/// What the coordinator's shutdown proved: `complete` only when every native
/// lifecycle it held stopped or was handed back; `pending` names the rest.
#[derive(Clone, Debug, Default)]
pub struct CustodyShutdown {
    pub complete: bool,
    pub pending: Vec<String>,
}
pub struct ExecutionCall {
    pub admitted: HostedCall,
    pub deadline: Deadline,
}

/// One request's executor result. Timings are moved out of its own awaited
/// store completion before the receipt is consumed by the core continuation.
/// Read-only and unmeasured completions carry None; never consult an aggregate.
#[derive(Clone, Debug)]
pub struct CommittedWrite {
    pub operation: String,
    pub key: Option<se_types::IdempotencyKey>,
    pub natural_events: Vec<se_types::EventId>,
    pub committed_events: Vec<se_types::EventId>,
}
pub struct ExecutedCall {
    pub host_phases: se_core::ops::HostPhaseTimings,
    pub output: se_core::ops::AnyOutput,
    pub write_timings: Option<se_store::WriteTimings>,
    pub committed: Option<CommittedWrite>,
    pub capture_commits: Vec<se_core::ops::CaptureCommitDiagnostics>,
    pub capture_keys: Vec<String>,
}
