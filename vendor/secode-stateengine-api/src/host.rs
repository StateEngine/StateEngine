// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::{
    ActiveSession, AdoptBinding, Adoption, AgentInfo, Authority, BindingAuthority,
    BindingObservation, BindingRequest, BoundSession, CallOptions, CapturedTurn, ContinuityRequest,
    DrainReceipt, EventRef, HandoverReport, HandoverRequest, HandoverServices, HoldReason,
    HoldReceipt, HostConfig, HostEpoch, HostFuture, HostSessionTarget, IdempotencyKey,
    InterruptReceipt, IssuedSession, MailNotice, Negotiated, NoticeAdmission, NoticeId,
    OpenOptions, OpenedHost, OwnerAuthority, Page, PageRequest, ProjectId, ProjectInfo, Read,
    Readiness, Receipt, RevokeRequest, ServiceOptions, SessionActivity, SessionCapability,
    SessionContext, SessionIdentity, TargetReceipt, TargetTransition, ToolCall, ToolDefinition,
    ToolOutput,
};
use std::sync::Arc;

/// The implementation/factory is configured with the embedding host's runtime.
/// No Tokio dependency or runtime creation belongs to this permissive API crate.
#[allow(
    missing_debug_implementations,
    reason = "protected grants and opaque runtime callbacks intentionally have no Debug surface"
)]
pub enum HostIntegration {
    Secode {
        epoch: HostEpoch,
        services: Arc<dyn HostServices>,
    },
}

pub trait HostFactory: Send + Sync {
    /// Cold open is preparation only: no writer, native mutation or callbacks.
    fn open<'a>(
        &'a self,
        config: HostConfig,
        options: OpenOptions,
    ) -> HostFuture<'a, Read<OpenedHost>>;
    /// Independent supervisor closes the old generation, then prepares a fresh one.
    fn restart<'a>(
        &'a self,
        reason: RestartReason,
        key: IdempotencyKey,
        options: CallOptions,
    ) -> HostFuture<'a, Read<OpenedHost>>;
    /// Retained coordinator; does not invoke a drained or poisoned Host object.
    fn handover<'a>(
        &'a self,
        request: HandoverRequest,
        native: Arc<dyn HandoverServices>,
        options: CallOptions,
    ) -> HostFuture<'a, Receipt<HandoverReport>>;
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RestartReason {
    Drained { receipt: DrainReceipt },
    Poisoned { incident: String },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GenerationHealth {
    Prepared,
    Activating,
    Ready,
    Recovering,
    Draining,
    Drained,
    Poisoned,
    Closed,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultReport {
    pub incident: String,
}

pub trait Host: Send + Sync {
    /// Owner-only selector reads. Each page has at most 100 rows and 64 KiB.
    /// Reject zero/excessive limits, max_bytes outside 1..=65536, or cursors
    /// above 256 UTF-8 bytes as Usage, code "selector-invalid-page".
    /// Opaque cursors bind operation, project, generation and catalog revision.
    /// Revision/generation changes return Conflict, "selector-stale-cursor",
    /// AfterRefresh; never splice old/new revisions or auto-restart pagination.
    /// Project order is ProjectId; agent order is AgentId; session order is
    /// (binding.agent, binding.session, epoch identity, host session).
    /// Page.window retains the existing completeness/omission distinctions.
    /// Bound ApiError code to 64 bytes, message/remedy.text to 2048 each;
    /// no provider/tool bodies or credentials in selector errors.
    fn list_projects<'a>(
        &'a self,
        authority: &'a OwnerAuthority,
        page: PageRequest,
        options: CallOptions,
    ) -> HostFuture<'a, Read<Page<ProjectInfo>>>;
    /// The project is checked before paging: Unknown is not an empty roster.
    /// name <= 256 bytes, role <= 2048 bytes, IDs <= 256 bytes; fail with
    /// Unreadable/selector-invalid-record rather than silently dropping records.
    fn list_agents<'a>(
        &'a self,
        authority: &'a OwnerAuthority,
        project: ProjectId,
        page: PageRequest,
        options: CallOptions,
    ) -> HostFuture<'a, Read<Page<AgentInfo>>>;
    /// Engine-side project-filtered diagnostic projection of existing host
    /// active_sessions pages. Each row's target.binding.project equals project.
    /// Unavailable/unreadable hosts make the result incomplete, never empty.
    /// No grant/capability is exposed; selecting a row cannot bind or take over.
    /// Kept separate from HostServices::active_sessions(epoch, ...), whose
    /// direction is host -> engine and whose diagnostic pages are not a catalog.
    fn project_active_sessions<'a>(
        &'a self,
        authority: &'a OwnerAuthority,
        project: ProjectId,
        page: PageRequest,
        options: CallOptions,
    ) -> HostFuture<'a, Read<Page<ActiveSession>>>;

    fn poison<'a>(
        &'a self,
        report: FaultReport,
        options: CallOptions,
    ) -> HostFuture<'a, GenerationHealth>;

    /// Non-blocking snapshots; no I/O or wait for worker threads.
    fn negotiated(&self) -> Negotiated;
    fn health(&self) -> GenerationHealth;
    fn wait_health<'a>(
        &'a self,
        after: GenerationHealth,
        options: CallOptions,
    ) -> HostFuture<'a, GenerationHealth>;
    /// Caller registers this handle/generation before this first mutating call.
    fn activate<'a>(
        &'a self,
        integration: HostIntegration,
        options: CallOptions,
    ) -> HostFuture<'a, Readiness>;
    fn verify_capability<'a>(
        &'a self,
        capability: &'a SessionCapability,
        options: CallOptions,
    ) -> HostFuture<'a, BoundSession>;
    fn open_project<'a>(
        &'a self,
        authority: &'a OwnerAuthority,
        project: ProjectId,
        options: CallOptions,
    ) -> HostFuture<'a, Read<ProjectInfo>>;
    fn bind_session<'a>(
        &'a self,
        authority: &'a BindingAuthority,
        request: BindingRequest,
        options: CallOptions,
    ) -> HostFuture<'a, IssuedSession>;
    fn revoke_session<'a>(
        &'a self,
        authority: &'a Authority,
        request: RevokeRequest,
        options: CallOptions,
    ) -> HostFuture<'a, Receipt<SessionIdentity>>;
    fn tools<'a>(
        &'a self,
        session: &'a BoundSession,
        page: PageRequest,
        options: CallOptions,
    ) -> HostFuture<'a, Page<ToolDefinition>>;
    fn call_tool<'a>(
        &'a self,
        session: &'a BoundSession,
        call: ToolCall,
        options: CallOptions,
    ) -> HostFuture<'a, ToolOutput>;
    fn continuity<'a>(
        &'a self,
        session: &'a BoundSession,
        request: ContinuityRequest,
        options: CallOptions,
    ) -> HostFuture<'a, SessionContext>;
    fn capture_turn<'a>(
        &'a self,
        session: &'a BoundSession,
        turn: CapturedTurn,
        options: CallOptions,
    ) -> HostFuture<'a, Receipt<EventRef>>;
    /// Nudge only: re-read eligibility/debt; cannot acknowledge admission or clear holds.
    fn native_state_changed<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        options: CallOptions,
    ) -> HostFuture<'a, ()>;
    fn adoption_status<'a>(
        &'a self,
        authority: &'a OwnerAuthority,
        page: PageRequest,
        options: CallOptions,
    ) -> HostFuture<'a, Page<Adoption>>;
    fn drain<'a>(&'a self, options: CallOptions) -> HostFuture<'a, DrainReceipt>;
    fn close<'a>(
        &'a self,
        drained: DrainReceipt,
        options: CallOptions,
    ) -> HostFuture<'a, DrainReceipt>;
}
/// SE Code owns admission and promotion of its one input queue.
/// StateEngine owns message bodies, recipient read/dismiss markers and debt.
pub trait HostServices: Send + Sync {
    fn hold<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        reason: HoldReason,
        key: IdempotencyKey,
        options: ServiceOptions,
    ) -> HostFuture<'a, HoldReceipt>;
    fn interrupt<'a>(
        &'a self,
        held: &'a HoldReceipt,
        options: ServiceOptions,
    ) -> HostFuture<'a, InterruptReceipt>;
    /// Point observation; Present(None) proves no active execution at this read.
    fn active_session<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        options: ServiceOptions,
    ) -> HostFuture<'a, Read<Option<ActiveSession>>>;
    /// Diagnostic pages cannot be combined into an absence proof.
    fn active_sessions<'a>(
        &'a self,
        epoch: &'a HostEpoch,
        page: PageRequest,
        options: ServiceOptions,
    ) -> HostFuture<'a, Read<Page<ActiveSession>>>;
    fn idle<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        options: ServiceOptions,
    ) -> HostFuture<'a, Read<SessionActivity>>;
    fn binding_state<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        options: ServiceOptions,
    ) -> HostFuture<'a, Read<BindingObservation>>;
    fn adopt_binding<'a>(
        &'a self,
        request: AdoptBinding,
        options: ServiceOptions,
    ) -> HostFuture<'a, Read<BindingObservation>>;
    fn update_mail_target<'a>(
        &'a self,
        transition: TargetTransition,
        key: IdempotencyKey,
        options: ServiceOptions,
    ) -> HostFuture<'a, TargetReceipt>;
    fn deliver_notice<'a>(
        &'a self,
        notice: &'a MailNotice,
        options: ServiceOptions,
    ) -> HostFuture<'a, NoticeAdmission>;
    fn notice_status<'a>(
        &'a self,
        target: &'a HostSessionTarget,
        notice: &'a NoticeId,
        options: ServiceOptions,
    ) -> HostFuture<'a, Read<NoticeAdmission>>;
}
