//! A remote launch cannot take over existing work or broaden its saved profile.
use super::*;
use crate::{client::lease::Deadline, remote::auth::AdmissionPermit};
use se_core::ops::{LaunchReply, agent_launch::LaunchPlan, delegate::DelegateStartPlan};
use se_store::{Actor, Admission, Scope};
use se_types::Result;

impl LaunchCoordinator {
    pub(super) async fn launch_remote_admitted(
        self: &Arc<Self>,
        mut plan: LaunchPlan,
        admission: Admission,
        permit: AdmissionPermit,
        deadline: &Deadline,
    ) -> Result<LaunchReply> {
        let stamp = plan
            .remote
            .as_ref()
            .ok_or_else(|| error("remote launch", "authenticated attribution is required"))?;
        if admission.actor != Actor::Remote(stamp.principal.clone())
            || admission.scope != Scope::Project(plan.project.id.clone())
            || admission.session.is_some()
            || plan.input.override_live
            || !plan.input.detach
            || (!plan.replayed
                && (!plan.control.processes.is_empty() || !plan.control.sessions.is_empty()))
        {
            return Err(error(
                "remote launch",
                "use an explicitly allowed idle agent and its saved launch profile; stop existing work through its native Owner before launching",
            ));
        }
        self.harness_for(plan.profile.provider)?;
        self.preflight_relaunch(&mut plan, &admission, deadline)
            .await?;
        self.launch_prepared(plan, admission, deadline, None, None, Some(permit))
            .await
    }

    /// A remote delegated worker: created under the caller's admitted permit,
    /// then started under its anchor's consent like any remote launch.
    pub(super) async fn delegate_remote_admitted(
        self: &Arc<Self>,
        plan: DelegateStartPlan,
        admission: Admission,
        permit: AdmissionPermit,
        deadline: &Deadline,
    ) -> Result<LaunchReply> {
        let origin = plan
            .remote
            .clone()
            .ok_or_else(|| error("remote delegation", "authenticated attribution is required"))?;
        if admission.actor != Actor::Remote(origin.attribution.principal.clone())
            || admission.scope != Scope::Project(plan.project.id.clone())
            || admission.session.is_some()
            || origin.anchor.project != plan.project.id
        {
            return Err(error(
                "remote delegation",
                "the native admission differs from the approved anchor's project",
            ));
        }
        let _owned = self
            .lock_delegation(&admission, &plan.idempotency_key, deadline)
            .await?;
        let write = super::delegate::CreateWrite::Remote(permit.for_next_write());
        let (agent, _, newly_created) = self
            .create_delegate(&plan, &admission, write, deadline)
            .await?;
        let reply = match self
            .plan_delegate_launch(&plan, &agent, &admission, deadline)
            .await
        {
            Ok(mut launch) => {
                launch.remote = Some(origin.attribution);
                launch.delegated_from = Some(origin.anchor);
                self.launch_remote_admitted(launch, admission.clone(), permit, deadline)
                    .await
            }
            Err(error) => Err(error),
        };
        self.settle_delegate(reply, newly_created, &plan, &agent, &admission, deadline)
            .await
    }
}
