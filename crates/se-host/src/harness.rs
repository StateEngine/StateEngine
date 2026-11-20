use crate::{CallContext, HarnessKind, HostFuture, SessionIdentity};
use se_types::{Body, IdempotencyKey, NativePath, ProviderSessionId, Read, Secret, Sha256};
use std::{ffi::OsString, future::Future, path::PathBuf, pin::Pin, sync::Arc};
#[cfg(feature = "listener")]
pub(crate) mod binding {
    //! Adapter-owned lifecycle operations on the original retained streams.
    use se_types::{ErrorBody, SeError};
    use std::{any::Any, sync::Arc, time::Instant};
    use tokio::sync::Notify;

    #[derive(Default)]
    pub(crate) struct Observation {
        pub observed_at: Option<Instant>,
        pub idle: Option<bool>,
        pub mail_pending: bool,
        pub capture_pending: bool,
        pub failure: Option<ErrorBody>,
        pub capture_failure: Option<SeError>,
    }

    #[derive(Clone, Copy)]
    pub(crate) enum Signal {
        Interrupt,
        #[cfg(target_os = "linux")]
        Terminate,
    }

    #[derive(Clone, Copy, Default)]
    pub(crate) struct StopPolicy {
        pub signal: Option<Signal>,
        pub native_window: bool,
    }

    pub(crate) trait AdapterBinding: Send + Sync {
        fn as_any(&self) -> &dyn Any;
        fn provider(&self) -> se_types::Provider;
        fn arm(&self, wake: &Arc<Notify>) -> se_types::Result<()>;
        fn observe(&self, capture: bool) -> Observation;
        fn stop_policy(&self) -> StopPolicy;
        fn start_initial(&self, _cx: crate::CallContext) -> crate::HostFuture<'_, ()> {
            Box::pin(async { Ok(()) })
        }
        fn policy_notice(&self) -> se_types::Result<Option<String>> {
            Ok(None)
        }
    }
}

/// Headless Claude launch plan: settings/MCP files, argv, readiness, transcript.
pub mod claude;
#[cfg(feature = "listener")]
mod claude_harness;
#[cfg(feature = "listener")]
pub use claude::{
    config_home as claude_config_home, conversation as claude_conversation, provider_environment,
};
#[cfg(feature = "listener")]
pub(crate) use claude_harness::{ADOPTION as CLAUDE_ADOPTION, Binding as ClaudeBinding};
#[cfg(feature = "listener")]
pub use claude_harness::{
    ClaudeHarness, qualify_adoption as qualify_claude_adoption,
    transcript_location as claude_transcript_location,
};
#[cfg(feature = "listener")]
pub mod codex_input;
#[cfg(feature = "listener")]
pub mod codex_rpc;
#[cfg(feature = "listener")]
pub use codex_rpc::CodexHarness;

#[cfg(feature = "listener")]
pub mod acp;
pub use se_codex_capture as codex_capture;
#[cfg(feature = "listener")]
pub(crate) mod progress;
#[cfg(feature = "secode")]
pub(crate) mod secode;
#[cfg(feature = "listener")]
pub use se_secode_image as secode_image;
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
    /// The launching owner terminal's provider sign-in, laid over the host's own
    /// for this launch only; `None` when no terminal launched it (restore, MCP).
    pub sign_in: Option<crate::launch_sign_in::SignIn>,
}
/// Credential purpose the loopback HTTP route accepts, and only it.
pub const MCP_BEARER_PURPOSE: &str = "http";
/// The host's retained ends of one provider's streams. Only the platform that
/// opened it can operate on it; the last reference owns the host ends.
#[derive(Clone)]
pub struct ProviderTransport {
    #[cfg(all(unix, feature = "listener"))]
    pub(crate) unix: Option<std::sync::Arc<crate::process_io::Pipes>>,
    #[cfg(all(windows, feature = "listener"))]
    pub(crate) windows: Option<std::sync::Arc<crate::process_io::Port>>,
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
    pub process: Arc<se_proc::OwnedProcess>,
    pub record: se_proc::ProcessRecord,
    pub transport: ProviderTransport,
    pub transcript: Read<crate::TranscriptPin>,
    pub provider_exit: ProviderExitProof,
}
/// Lazy proof that the provider exited on its own with a witnessed native
/// exit. Evaluated only when the protocol handshake fails; a live process
/// stays unproven, so the real protocol error is preserved.
pub type ProviderExitProof =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = bool> + Send>> + Send + Sync>;
/// One adapter's streams, retained through startup as well as a proven attach.
/// Only the adapter modules construct it; empty and mixed bindings are impossible.
pub struct HarnessBinding {
    #[cfg(feature = "listener")]
    value: Box<dyn binding::AdapterBinding>,
    #[cfg(not(feature = "listener"))]
    _private: (),
}
impl HarnessBinding {
    #[cfg(feature = "listener")]
    fn new<T: Send + Sync + 'static>(binding: std::sync::Arc<T>) -> Self
    where
        std::sync::Arc<T>: binding::AdapterBinding,
    {
        Self {
            value: Box::new(binding),
        }
    }

    #[cfg(feature = "listener")]
    pub(crate) fn get<T: Send + Sync + 'static>(&self) -> Option<&std::sync::Arc<T>> {
        self.value.as_any().downcast_ref()
    }

    #[cfg(feature = "listener")]
    pub(crate) fn provider(&self) -> se_types::Provider {
        self.value.provider()
    }

    #[cfg(feature = "listener")]
    pub(crate) fn arm(&self, wake: &std::sync::Arc<tokio::sync::Notify>) -> se_types::Result<()> {
        self.value.arm(wake)
    }

    #[cfg(feature = "listener")]
    pub(crate) fn observe(&self, capture: bool) -> binding::Observation {
        self.value.observe(capture)
    }

    #[cfg(feature = "listener")]
    pub(crate) fn stop_policy(&self) -> binding::StopPolicy {
        self.value.stop_policy()
    }

    #[cfg(feature = "listener")]
    pub(crate) fn start_initial(&self, cx: CallContext) -> HostFuture<'_, ()> {
        self.value.start_initial(cx)
    }

    #[cfg(feature = "listener")]
    pub(crate) fn policy_notice(&self) -> se_types::Result<Option<String>> {
        self.value.policy_notice()
    }
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
/// Reconnect only the original, natively verified provider session.
pub struct HarnessRecovery<'a> {
    pub identity: &'a SessionIdentity,
    pub conversation: &'a ProviderSessionId,
    pub transcript: Option<&'a crate::TranscriptPin>,
    pub attended: bool,
    pub retained: Option<&'a HarnessBinding>,
}
pub type TranscriptValidator =
    fn(&mut se_proc::NativeSourcePin, &ProviderSessionId) -> se_types::Result<()>;
/// Closed enum selection is performed by composition; no dynamic plugin loader.
/// Partial launch failure remains owned by the process arena, never dropped.
pub trait Harness: Send + Sync {
    fn kind(&self) -> HarnessKind;
    /// Load the complete saved canonical projection before protocol resume.
    fn canonical_resume(&self) -> bool {
        false
    }
    /// Prepare adapter-owned rendezvous after launch files have been published.
    fn prepare<'a>(&'a self, _request: &'a HarnessRequest, _cx: CallContext) -> HostFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    /// The adapter's native transcript, or no file for a protocol capture source.
    fn transcript_path(&self, binding: &HarnessBinding) -> se_types::Result<Option<PathBuf>>;
    /// A fresh transcript may follow the provider's readiness echo.
    fn transcript_wait(&self) -> Option<std::time::Duration> {
        None
    }
    fn materialize_transcript<'a>(
        &'a self,
        _binding: &'a HarnessBinding,
        _cx: CallContext,
    ) -> HostFuture<'a, Option<se_types::SeError>> {
        Box::pin(async { Ok(None) })
    }
    fn transcript_validator(&self) -> TranscriptValidator {
        |_, _| Ok(())
    }
    fn recover<'a>(
        &'a self,
        _request: HarnessRecovery<'a>,
        _cx: CallContext,
    ) -> HostFuture<'a, HarnessBinding> {
        Box::pin(async {
            Err(se_core::scope::unreadable(
                "provider restart control",
                "the original stdin stream cannot be reopened; preserve the session and use its exact public stop/resume command",
            ))
        })
    }
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
