//! Retained native custody and cleanup obligations for one lifecycle. Recovered
//! records carry metadata, never a fabricated launch authorization.
use super::*;
use se_core::ops::agent_launch::LaunchPlan;
use se_store::Admission;
#[derive(Clone)]
pub(super) struct LifecycleMetadata {
    pub project: se_types::Named<se_types::ProjectId>,
    pub agent: se_types::Named<se_types::AgentId>,
    pub owner: se_types::HumanId,
    pub session: se_types::SessionId,
    pub lifecycle: se_types::LifecycleId,
    pub request: se_types::IdempotencyKey,
    pub conversation: se_types::Read<se_types::ProviderSessionId>,
    pub model: Option<String>,
    pub provider: se_store::Provider,
    pub capture: bool,
    pub attended: bool,
}
impl LifecycleMetadata {
    pub fn from_launch(plan: &LaunchPlan) -> Self {
        Self {
            project: plan.project.clone(),
            agent: plan.agent.clone(),
            owner: plan.owner.clone(),
            session: plan.session.clone(),
            lifecycle: plan.lifecycle.clone(),
            request: plan.input.idempotency_key.clone(),
            conversation: plan.conversation.clone(),
            model: plan.profile.model.clone(),
            provider: plan.profile.provider,
            capture: plan.capture,
            attended: !plan.input.detach,
        }
    }
}
pub(super) struct Work {
    pub takeover: Option<se_core::ops::agent_launch::TakeoverReport>,
    pub plan: Option<Arc<LaunchPlan>>,
    pub recover_provider: bool,
    pub meta: LifecycleMetadata,
    pub admission: Admission,
    pub cleanup_admission: Admission,
    pub process: Option<Arc<se_proc::OwnedProcess>>,
    pub record: Option<se_proc::ProcessRecord>,
    pub exec_observed: bool,
    pub process_view: Option<se_core::ops::ProcessView>,
    pub binding: Option<crate::HarnessBinding>,
    pub mail: super::mail::State,
    pub wake: Arc<events::Wake>,
    pub committed: bool,
    pub reservation_uncertain: bool,
    pub reservation: Option<se_proc::LaunchReservation>,
    pub session_retired: bool,
    pub credentials_revoked: bool,
    pub process_retired: bool,
    pub native_already_reconciled: bool,
    pub exit_watch: Option<se_proc::ExitWatch>,
    pub released: bool,
    pub last_witness: Option<se_proc::StopWitness>,
    pub ownership_release: Option<se_proc::UnwitnessedRelease>,
    pub last_stop_event: Option<se_types::EventId>,
    pub stop_method: Option<String>,
    pub stop_failure: Option<se_types::ErrorBody>,
    pub stop_key: Option<se_types::IdempotencyKey>,
    pub capture_flushed: bool,
    pub capture_failure: Option<se_types::ErrorBody>,
    pub last_capture: Option<se_types::EventId>,
    pub transcript: Option<crate::TranscriptPin>,
    pub capture_source: Option<se_store::RecordId>,
    pub active: bool,
    pub activated: bool,
    pub cleanup_failure: Option<se_types::ErrorBody>,
    pub pin_hash: Option<[u8; 32]>,
    pub cleanup_files_known: bool,
    pub files: Vec<(PathBuf, [u8; 32])>,
}
impl Work {
    pub fn new(plan: LaunchPlan, admission: Admission) -> Self {
        let mut work = Self::recovered(LifecycleMetadata::from_launch(&plan), admission);
        work.plan = Some(Arc::new(plan));
        work.committed = false;
        work.cleanup_files_known = true;
        work
    }
    pub fn recovered(meta: LifecycleMetadata, admission: Admission) -> Self {
        let mut cleanup_admission = admission.clone();
        cleanup_admission.actor = se_store::Actor::Human(meta.owner.clone());
        cleanup_admission.session = None;
        Self {
            takeover: None,
            cleanup_admission,
            meta,
            plan: None,
            recover_provider: false,
            admission,
            process: None,
            record: None,
            exec_observed: false,
            process_view: None,
            binding: None,
            mail: super::mail::State::default(),
            wake: Arc::new(events::Wake::default()),
            committed: true,
            reservation_uncertain: false,
            reservation: None,
            session_retired: false,
            credentials_revoked: false,
            process_retired: false,
            native_already_reconciled: false,
            exit_watch: None,
            released: false,
            last_witness: None,
            ownership_release: None,
            last_stop_event: None,
            stop_method: None,
            stop_failure: None,
            stop_key: None,
            capture_flushed: false,
            capture_failure: None,
            last_capture: None,
            transcript: None,
            capture_source: None,
            active: false,
            activated: false,
            cleanup_failure: None,
            pin_hash: None,
            cleanup_files_known: false,
            files: Vec::new(),
        }
    }
}
