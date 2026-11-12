use crate::{CallContext, HarnessKind, HostFuture, SessionIdentity};
use se_types::{Body, IdempotencyKey, NativePath, ProviderSessionId, Read, Secret, Sha256};
use std::{ffi::OsString, path::PathBuf};

/// Headless Claude launch plan: settings/MCP files, argv, readiness, transcript.
pub mod claude;
#[cfg(feature = "listener")]
mod claude_harness;
#[cfg(feature = "listener")]
pub use claude::{
    config_home as claude_config_home, conversation as claude_conversation, provider_environment,
};
#[cfg(feature = "listener")]
pub use claude_harness::{ClaudeHarness, transcript_location as claude_transcript_location};
#[cfg(feature = "listener")]
pub mod codex_input;
#[cfg(feature = "listener")]
pub mod codex_rpc;
#[cfg(feature = "listener")]
pub use codex_rpc::CodexHarness;

#[cfg(feature = "listener")]
pub mod acp;
pub mod codex_capture;
#[cfg(feature = "listener")]
pub(crate) mod progress;
#[cfg(feature = "secode")]
pub(crate) mod secode;
#[cfg(all(feature = "listener", test))]
mod secode_image_fixture;
#[cfg(feature = "listener")]
pub mod secode_process;
#[cfg(feature = "listener")]
pub(crate) mod tool_capture;

/// One stock Codex feature/version floor for every launch/probe mode.
pub const CODEX_MINIMUM_VERSION: (u16, u16, u16) = (0, 152, 0);

#[derive(Clone, Debug)]
pub struct ProviderVersion {
    pub kind: HarnessKind,
    pub executable: NativePath,
    pub version: String,
    pub protocol: String,
}
pub struct ProbeRequest {
    pub kind: HarnessKind,
    pub command: PathBuf,
}
pub struct ConfigPlan {
    pub edits: Vec<IntegrationEdit>,
    pub ephemeral_files: Vec<OwnedLaunchFile>,
}
#[derive(Clone, Debug)]
pub struct IntegrationEdit {
    pub path: NativePath,
    pub key: String,
    pub prior_digest: Read<Sha256>,
    pub replacement: Vec<u8>,
}
pub struct OwnedLaunchFile {
    pub path: NativePath,
    pub contents: Secret,
}
pub struct HarnessRequest {
    pub identity: SessionIdentity,
    pub executable: NativePath,
    pub cwd: NativePath,
    pub profile: se_store::Profile,
    pub policy: se_proc::LaunchPolicy,
    pub mode: se_proc::LaunchMode,
    pub resume: Read<ProviderSessionId>,
    /// Every registered project root moved away from, newest move first. A
    /// resumed provider transcript stays under the slug of the root where it
    /// was written, so the transcript watch probes these before cwd.
    pub transcript_roots: Vec<NativePath>,
    /// Complete canonical text projection for protocol resume, never a recent window.
    #[cfg(feature = "listener")]
    pub replay: Option<Vec<crate::acp::CapturedMessage>>,
    pub initial_input: Body,
    /// The `sec1.` pin capability hooks resolve through `SE_SESSION`.
    pub launch_credential: Secret,
    /// The separate `sels-` loopback MCP bearer, a credential of purpose
    /// `MCP_BEARER_PURPOSE` issued and activated with the session; written only
    /// into the protected per-launch MCP config.
    pub mcp_bearer: Secret,
    pub key: IdempotencyKey,
}
/// Credential purpose the loopback HTTP route accepts, and only it.
pub const MCP_BEARER_PURPOSE: &str = "http";
/// The host's retained ends of one provider's streams. Only the platform that
/// opened it can operate on it; dropping it closes the host ends.
pub struct ProviderTransport {
    #[cfg(all(unix, feature = "listener"))]
    pub(crate) unix: Option<crate::process_io::Pipes>,
    #[cfg(all(windows, feature = "listener"))]
    pub(crate) windows: Option<crate::process_io::Port>,
    pub(crate) _private: (),
}
impl ProviderTransport {
    /// A provider console is owned by the native process, with no host pipes.
    #[cfg(feature = "listener")]
    pub(crate) fn console() -> Self {
        Self {
            #[cfg(all(unix, feature = "listener"))]
            unix: None,
            #[cfg(all(windows, feature = "listener"))]
            windows: None,
            _private: (),
        }
    }
}
pub struct ProviderIo {
    pub child: se_proc::StandardIo,
    pub host: ProviderTransport,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderStream {
    Input,
    Output,
    Error,
}
pub enum StreamRead {
    Bytes(Vec<u8>),
    Eof,
    Failed {
        bytes: Vec<u8>,
        error: se_types::ErrorBody,
    },
}
pub struct StreamWrite {
    pub completed_bytes: u32,
    pub failure: Option<se_types::ErrorBody>,
}
/// Genuine Unix/Windows evented I/O implementations. The Windows implementation
/// (`WindowsProviderIo`) wraps se-proc's safe native IOCP port; se-host performs
/// no blocking File wrapper or raw-handle conversion.
pub trait ProviderIoPlatform: Send + Sync {
    fn open(
        &self,
        owner: &se_proc::OwnedProcess,
        identity: &SessionIdentity,
    ) -> se_types::Result<ProviderIo>;
    fn read<'a>(
        &'a self,
        transport: &'a ProviderTransport,
        stream: ProviderStream,
        maximum_bytes: std::num::NonZeroU32,
        cx: CallContext,
    ) -> HostFuture<'a, StreamRead>;
    fn write<'a>(
        &'a self,
        transport: &'a ProviderTransport,
        bytes: Vec<u8>,
        cx: CallContext,
    ) -> HostFuture<'a, StreamWrite>;
    /// Finish an accepted stdin write and close only host stdin; output reads live.
    fn finish_input<'a>(
        &'a self,
        transport: &'a ProviderTransport,
        cx: CallContext,
    ) -> HostFuture<'a, ()>;
    fn close<'a>(&'a self, transport: &'a ProviderTransport, cx: CallContext)
    -> HostFuture<'a, ()>;
}
pub struct ProviderInvocation {
    pub executable: NativePath,
    pub arguments: Vec<OsString>,
    pub environment: se_proc::Environment,
}
pub struct HarnessAttach {
    pub request: HarnessRequest,
    pub process: se_proc::OwnedProcess,
    pub record: se_proc::ProcessRecord,
    pub transport: ProviderTransport,
    pub transcript: Read<crate::TranscriptPin>,
}
/// Provider streams retained through startup as well as a proven attach.
pub struct HarnessBinding {
    #[cfg(feature = "listener")]
    pub(crate) claude: Option<std::sync::Arc<claude_harness::Binding>>,
    #[cfg(feature = "listener")]
    pub(crate) codex: Option<std::sync::Arc<codex_rpc::Binding>>,
    #[cfg(feature = "listener")]
    pub(crate) secode: Option<std::sync::Arc<secode_process::Binding>>,
    #[cfg(feature = "listener")]
    pub(crate) acp: Option<std::sync::Arc<acp::Binding>>,
    pub(crate) _private: (),
}
#[derive(Clone, Debug)]
pub struct BindingWitness {
    pub identity: SessionIdentity,
    pub conversation: ProviderSessionId,
    pub lifecycle: se_types::LifecycleId,
    pub provider: ProviderVersion,
}
pub struct LaunchOutcome {
    pub binding: HarnessBinding,
    pub witness: BindingWitness,
}
#[derive(Clone, Debug)]
pub struct ProviderInterrupt {
    pub conversation: ProviderSessionId,
    pub requested: bool,
    pub vendor_event: Read<String>,
}
/// Closed enum selection is performed by composition; no dynamic plugin loader.
/// Partial launch failure remains owned by the process arena, never dropped.
pub trait Harness: Send + Sync {
    fn kind(&self) -> HarnessKind;
    fn probe<'a>(
        &'a self,
        request: ProbeRequest,
        cx: CallContext,
    ) -> HostFuture<'a, ProviderVersion>;
    /// A final selected invocation may reuse immutable executable qualification.
    /// Alias-image discovery calls `probe` instead and always remains fresh.
    fn probe_direct<'a>(
        &'a self,
        request: ProbeRequest,
        _stamp: Option<se_proc::native_ipc::ExecutableStamp>,
        cx: CallContext,
    ) -> HostFuture<'a, ProviderVersion> {
        self.probe(request, cx)
    }
    fn configuration<'a>(
        &'a self,
        request: &'a HarnessRequest,
        cx: CallContext,
    ) -> HostFuture<'a, ConfigPlan>;
    fn invocation<'a>(
        &'a self,
        request: &'a HarnessRequest,
        cx: CallContext,
    ) -> HostFuture<'a, ProviderInvocation>;
    /// Partial stream custody published through `retained` survives an attach
    /// failure or panic and is closed by the coordinator's normal cleanup.
    fn attach<'a>(
        &'a self,
        request: HarnessAttach,
        retained: &'a mut Option<HarnessBinding>,
        cx: CallContext,
    ) -> HostFuture<'a, LaunchOutcome>;
    fn graceful_stop<'a>(
        &'a self,
        binding: &'a HarnessBinding,
        cx: CallContext,
    ) -> HostFuture<'a, ProviderInterrupt>;
    /// After the coordinator has witnessed the provider closed: stop this
    /// binding's stream readers and release every host stream end. Borrowed,
    /// so a failed or timed-out close keeps the binding for a retry.
    fn close_binding<'a>(
        &'a self,
        binding: &'a HarnessBinding,
        cx: CallContext,
    ) -> HostFuture<'a, ()>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaudeHookKind {
    SessionStart,
    Prompt,
    Stop,
    StopFailure,
}
pub struct ClaudeHookInput {
    pub kind: ClaudeHookKind,
    pub conversation: ProviderSessionId,
    pub claimed_transcript: NativePath,
    pub payload: serde_json::Value,
}
