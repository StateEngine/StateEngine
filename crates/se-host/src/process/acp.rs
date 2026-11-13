//! Protocol completion/canonical capture composition, with native custody unchanged.
use super::*;
mod capture;
mod replay;
mod status;

impl LaunchCoordinator {
    pub(in crate::process) async fn preflight_acp(
        &self,
        plan: &mut se_core::ops::agent_launch::LaunchPlan,
        admission: &se_store::Admission,
        deadline: &crate::client::lease::Deadline,
    ) -> se_types::Result<()> {
        crate::harness::acp::AcpHarness::validate_launch(
            &self.options.configuration,
            &plan.profile.named_profile,
            plan.profile.model.as_deref(),
            plan.profile.harness.as_deref(),
        )?;
        let harness = plan.profile.harness.clone();
        let configuration = self.options.configuration.clone();
        let selected_file = self.configuration_file.clone();
        self.store
            .pool
            .run_owned(deadline, move || {
                super::launch_util::resolve_provider(
                    &configuration,
                    se_types::Provider::Acp,
                    selected_file.as_deref(),
                    harness.as_deref(),
                )
            })
            .await?;
        // Refuse known capture/budget failures before stopping an incumbent.
        // Launch reads again after final capture; a live tail is never frozen here.
        if let Err(failure) = self.acp_replay(plan, admission, deadline).await {
            if !plan.input.override_live {
                return Err(failure);
            }
            plan.start_new_conversation(format!("Forced relaunch preserved the previous history and starts a new conversation because complete protocol replay was unavailable: {failure}"));
        }
        Ok(())
    }
}
