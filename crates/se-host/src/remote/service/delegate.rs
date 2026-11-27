//! A remote worker is planned under its anchor's consent, created and started
//! by the native coordinator, and reported through the launch receipt path.
use super::*;
use super::{failure, launch::result};
use se_core::dispatch::Kernel;
use se_store::{Actor, Admission, Scope};

impl Service {
    pub(super) async fn delegate(
        &self,
        request: auth::AuthorizedRemoteRequest,
    ) -> Result<RemoteDelegateResult> {
        self.router.check_open()?;
        let (authority, request, attribution, permit) = request.into_parts();
        let RemoteRequest::Delegate(input) = request else {
            return Err(SeError::invalid(
                "remote delegate",
                "an authorized delegate request",
            ));
        };
        let configuration = self.router.context.configuration.clone().ok_or_else(|| {
            SeError::invalid(
                "remote delegate",
                "readable saved destination delegation configuration",
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
                    "remote delegate",
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
        let key = input.idempotency_key.clone();
        let project = input.target.project.clone();
        let plan = store
            .read(admission.clone(), &deadline, move |cx| {
                let kernel = Kernel::new(crate::runtime::start::allocate_facts()?)?;
                se_core::remote::plan_delegate(
                    authority,
                    input,
                    attribution,
                    &kernel,
                    &configuration,
                    cx,
                )
            })
            .await?;
        let se_core::ops::delegate::RemoteDelegation {
            anchor,
            attribution,
        } = plan.remote.clone().ok_or_else(|| {
            SeError::invalid("remote delegate", "the planned authenticated origin")
        })?;
        let native_key =
            se_core::ops::process_commit::phase_key(&plan.idempotency_key, "delegate-launch")?;
        let (planned_agent, replayed) = (plan.agent_id.clone(), plan.existing_agent.is_some());
        let reply = custody
            .delegate_remote(plan, admission.clone(), permit, &deadline)
            .await
            .map_err(|error| failure::original_key(error, "remote.delegate", &key))?;
        // The worker is the one the store committed and launched.
        let agent = match &reply {
            se_core::ops::LaunchReply::Running(launched) => launched.agent.clone(),
            se_core::ops::LaunchReply::Pending(pending) => pending.agent.clone(),
        };
        let completion = result::Completion {
            target: RemoteTarget {
                project,
                agent: agent.id.clone(),
            },
            key: key.clone(),
            operation: "remote.delegate",
            attribution,
            admission: admission.clone(),
            native_key,
            replayed: replayed || agent.id != planned_agent,
        };
        let launched = result::finish(self, &store, completion, reply, &deadline).await?;
        let worker = store
            .read(admission, &deadline, move |cx| {
                se_core::remote::saved_worker(cx, &anchor, &agent.id, &agent.name)
            })
            .await?;
        Ok(RemoteDelegateResult {
            schema: RemoteDelegateResult::SCHEMA.into(),
            body: RemoteDelegateBody {
                outcome: launched.body.outcome,
                worker,
                attribution: launched.body.attribution,
            },
        })
    }
}
