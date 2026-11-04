//! The shared host executor dispatches only typed, already admitted plans.
use super::*;
use crate::{CustodyExecutor, HostFuture, client::lease::Deadline};
use se_core::{ops::AnyOutput, ports::CustodyPlan};
use se_store::Admission;
impl CustodyExecutor for Arc<LaunchCoordinator> {
    fn import_profiles(&self) -> se_types::Result<Vec<se_store::Profile>> {
        use se_core::config_policy::{EffectiveSandbox, Provider};
        let providers = match self.options.configuration.launch.provider {
            Provider::Claude => [Provider::Claude, Provider::Codex],
            Provider::Codex => [Provider::Codex, Provider::Claude],
        };
        providers
            .map(|provider| {
                (
                    provider,
                    match provider {
                        Provider::Claude => se_store::Provider::Claude,
                        Provider::Codex => se_store::Provider::Codex,
                    },
                )
            })
            .into_iter()
            .map(|(provider, stored)| {
                let profile = self
                    .options
                    .configuration
                    .resolve_profile("default", provider, false)?;
                let permission = match profile.sandbox {
                    EffectiveSandbox::ReadOnly => se_store::PermissionProfile::ReadOnly,
                    EffectiveSandbox::WorkspaceWrite => se_store::PermissionProfile::WorkspaceWrite,
                    EffectiveSandbox::Bypass => {
                        return Err(se_core::scope::unreadable(
                            "import default profile",
                            "a default profile cannot activate bypass",
                        ));
                    }
                };
                Ok(se_store::Profile {
                    provider: stored,
                    model: None,
                    permission,
                    named_profile: "default".into(),
                    effort: None,
                })
            })
            .collect()
    }
    fn shutdown<'a>(&'a self, deadline: &'a Deadline) -> HostFuture<'a, crate::CustodyShutdown> {
        Box::pin(async move {
            let report = LaunchCoordinator::shutdown(self, deadline).await?;
            Ok(crate::CustodyShutdown {
                complete: report.complete,
                pending: report.pending,
            })
        })
    }
    fn execute<'a>(
        &'a self,
        plan: CustodyPlan,
        admission: Admission,
        deadline: &'a Deadline,
    ) -> HostFuture<'a, AnyOutput> {
        Box::pin(async move {
            match plan {
                CustodyPlan::ObserveStatus(input) => self.status(input, admission, deadline).await,
                CustodyPlan::Launch(plan) => self
                    .launch(*plan, admission, deadline)
                    .await
                    .map(AnyOutput::from),
                CustodyPlan::Stop(plan) => self
                    .stop(*plan, admission, deadline)
                    .await
                    .map(AnyOutput::from),
                CustodyPlan::Remove(plan) => self
                    .remove(*plan, admission, deadline)
                    .await
                    .map(AnyOutput::from),
                _ => Err(se_core::scope::unreadable(
                    "native process operation",
                    "this plan belongs to the owner runtime, installer or trusted hook adapter",
                )),
            }
        })
    }
}
