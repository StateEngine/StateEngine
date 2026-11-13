//! Closed saved-profile launches retain native custody and their boundary permit.
use super::*;
use se_core::{dispatch::Kernel, ops::LaunchReply};
use se_store::{Actor, Admission, Scope};
mod receipt;

impl Service {
    pub(super) async fn launch(
        &self,
        request: auth::AuthorizedRemoteRequest,
    ) -> Result<RemoteLaunchResult> {
        self.router.check_open()?;
        let (authority, request, attribution, permit) = request.into_parts();
        let RemoteRequest::Launch(input) = request else {
            return Err(SeError::invalid(
                "remote launch",
                "an authorized launch request",
            ));
        };
        let configuration = self.router.context.configuration.clone().ok_or_else(|| {
            SeError::invalid(
                "remote launch",
                "readable saved native launch configuration",
            )
        })?;
        let custody = self
            .router
            .execution
            .custody
            .get()
            .cloned()
            .ok_or_else(|| {
                SeError::invalid(
                    "remote launch",
                    "the destination native process coordinator",
                )
            })?;
        let admission = Admission {
            actor: Actor::Remote(authority.grant().principal.clone()),
            scope: Scope::Project(input.target.project.clone()),
            session: None,
            generation: self.router.execution.generation.get(),
        };
        let deadline =
            crate::client::lease::Deadline::from_options(&crate::client::ClientOptions {
                expected_generation: Some(self.router.execution.generation),
                timeout: Duration::from_secs(30),
                cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            })?;
        let store = crate::runtime::store::Store::for_execution(&self.router.execution);
        let planned_input = input.clone();
        let planned_attribution = attribution.clone();
        let plan = store
            .read(admission.clone(), &deadline, move |cx| {
                let kernel = Kernel::new(crate::runtime::start::allocate_facts()?)?;
                se_core::remote::plan_launch(
                    authority,
                    planned_input,
                    planned_attribution,
                    &kernel,
                    &configuration,
                    cx,
                )
            })
            .await?;
        let replayed = plan.replayed;
        let native_key = plan.input.idempotency_key.clone();
        let reply = custody
            .launch_remote(plan, admission.clone(), permit, &deadline)
            .await?;
        let (outcome, attribution) = match reply {
            LaunchReply::Pending(value) => {
                let outcome = RemoteLaunchOutcome::Pending {
                    launch: RemoteLaunchStarted {
                        target: input.target,
                        session: value.session_id,
                        lifecycle: value.lifecycle_id,
                    },
                    idempotency_key: input.idempotency_key,
                    setup_needed: matches!(
                        value.state,
                        se_core::ops::LaunchPendingState::SetupNeeded
                    ),
                };
                (outcome, attribution)
            }
            LaunchReply::Running(value) => {
                let launched = RemoteLaunchStarted {
                    target: input.target,
                    session: value.session_id,
                    lifecycle: value.lifecycle_id,
                };
                let (receipt, origin) = receipt::read_back(
                    &store,
                    admission,
                    native_key,
                    launched,
                    &attribution,
                    &deadline,
                )
                .await?;
                let position = receipt::seal(self, &receipt, &origin)?;
                let commit = se_types::Commit {
                    event_id: receipt.primary_event,
                    position,
                    idempotency_key: input.idempotency_key,
                    value: RemoteLaunchStarted {
                        target: origin.target,
                        session: origin.session,
                        lifecycle: origin.lifecycle,
                    },
                    effects: se_types::EffectStatus::NotRequired,
                };
                let receipt = if replayed {
                    se_types::Receipt::Replayed { original: commit }
                } else {
                    se_types::Receipt::Committed { commit }
                };
                (RemoteLaunchOutcome::Running { receipt }, origin.attribution)
            }
        };
        Ok(RemoteLaunchResult {
            schema: RemoteLaunchResult::SCHEMA.into(),
            body: RemoteLaunchBody {
                outcome,
                attribution,
            },
        })
    }
}
