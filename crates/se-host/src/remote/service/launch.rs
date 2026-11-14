//! Closed saved-profile launches retain native custody and their boundary permit.
use super::*;
use se_core::{dispatch::Kernel, ops::LaunchReply};
use se_store::{Actor, Admission, Scope};
mod failure;
mod result;

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
        let launched = RemoteLaunchStarted {
            target: input.target.clone(),
            session: plan.session.clone(),
            lifecycle: plan.lifecycle.clone(),
        };
        let seed = plan.seed.clone();
        let key = input.idempotency_key.clone();
        let completion = result::Completion {
            input,
            attribution,
            admission: admission.clone(),
            native_key: native_key.clone(),
            replayed,
        };
        let activated = if replayed {
            let launch = launched.clone();
            store
                .read(admission.clone(), &deadline, move |cx| {
                    se_core::remote::launch_activated(cx, native_key, launch)
                })
                .await?
        } else {
            false
        };
        if activated {
            return result::started(self, &store, completion, launched, seed, &deadline).await;
        }
        let reply = custody
            .launch_remote(plan, admission.clone(), permit, &deadline)
            .await
            .map_err(|error| failure::original_key(error, &key))?;
        result::finish(self, &store, completion, reply, &deadline).await
    }
}
