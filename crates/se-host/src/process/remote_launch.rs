//! A remote launch cannot take over existing work or broaden its saved profile.
use super::*;
use crate::{client::lease::Deadline, remote::auth::AdmissionPermit};
use se_core::ops::{LaunchReply, agent_launch::LaunchPlan};
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
        self.launch_prepared(plan, admission, deadline, None, Some(permit))
            .await
    }
}
