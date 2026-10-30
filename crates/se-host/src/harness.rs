use crate::{
    BoundSession, CallContext, CaptureInput, HarnessKind, HoldReason, HostFuture, MailNotice,
    SessionIdentity, SessionLease,
};
use se_types::{Body, IdempotencyKey, NativePath, ProviderSessionId, Read, Secret, Sha256};
use std::{ffi::OsString, path::PathBuf};

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
pub struct HarnessLaunch {
    pub identity: SessionIdentity,
    pub lease: SessionLease,
    pub executable: NativePath,
    pub cwd: NativePath,
    pub profile: se_store::Profile,
    pub policy: se_proc::LaunchPolicy,
    pub mode: se_proc::LaunchMode,
    pub resume: Read<ProviderSessionId>,
    pub initial_input: Body,
    pub launch_credential: Secret,
    pub key: IdempotencyKey,
}
pub struct HarnessBinding {
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfferStage {
    TransportWritten,
    InputAccepted,
}
#[derive(Clone, Debug)]
pub struct OfferWitness {
    pub notice: se_types::NoticeId,
    pub identity: SessionIdentity,
    pub conversation: ProviderSessionId,
    pub digest: Sha256,
    pub stage: OfferStage,
    pub vendor_event: Read<String>,
}
#[derive(Clone, Debug)]
pub enum BellOutcome {
    Offered(OfferWitness),
    Held { reason: HoldReason },
    Refused(se_types::ErrorBody),
}
#[derive(Clone, Debug)]
pub struct TranscriptSource {
    pub path: Read<NativePath>,
    pub conversation: ProviderSessionId,
    pub next_offset: u64,
    pub incarnation: Sha256,
}
#[derive(Clone, Debug)]
pub enum HarnessStop {
    Exited { witness: Box<se_proc::StopWitness> },
    Bounded { witness: Box<se_proc::StopWitness> },
    StillOwned { reason: se_types::ErrorBody },
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
    fn configuration<'a>(
        &'a self,
        request: &'a HarnessLaunch,
        cx: CallContext,
    ) -> HostFuture<'a, ConfigPlan>;
    fn launch<'a>(
        &'a self,
        request: HarnessLaunch,
        cx: CallContext,
    ) -> HostFuture<'a, LaunchOutcome>;
    fn adopt<'a>(
        &'a self,
        witness: BindingWitness,
        cx: CallContext,
    ) -> HostFuture<'a, Read<HarnessBinding>>;
    fn bell<'a>(
        &'a self,
        binding: &'a HarnessBinding,
        notice: &'a MailNotice,
        cx: CallContext,
    ) -> HostFuture<'a, BellOutcome>;
    fn transcript<'a>(
        &'a self,
        binding: &'a HarnessBinding,
        cx: CallContext,
    ) -> HostFuture<'a, Read<TranscriptSource>>;
    fn capture<'a>(
        &'a self,
        session: &'a BoundSession,
        input: CaptureInput,
        cx: CallContext,
    ) -> HostFuture<'a, se_types::Receipt<se_types::EventId>>;
    fn graceful_stop<'a>(
        &'a self,
        binding: &'a HarnessBinding,
        cx: CallContext,
    ) -> HostFuture<'a, HarnessStop>;
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
    pub transcript: NativePath,
    pub payload: serde_json::Value,
}
pub struct HookOutput {
    pub stdout: Vec<u8>,
    pub captured: Read<se_types::EventId>,
    pub failure: Option<se_types::ErrorBody>,
}
pub trait ClaudeHookAdapter: Send + Sync {
    fn hook<'a>(
        &'a self,
        session: &'a BoundSession,
        input: ClaudeHookInput,
        cx: CallContext,
    ) -> HostFuture<'a, HookOutput>;
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodexTransport {
    StdioJsonLines,
    UnixWebSocket,
}
pub struct CodexInvocation {
    pub executable: NativePath,
    pub arguments: Vec<OsString>,
    pub transport: CodexTransport,
    pub private_endpoint: Option<NativePath>,
}
