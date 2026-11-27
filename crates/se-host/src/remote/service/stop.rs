//! Stop one recorded remote launch through the ordinary native stop path.
use super::*;
use se_store::{Actor, Admission, Scope};

impl Service {
    pub(super) async fn stop(
        &self,
        request: auth::AuthorizedRemoteRequest,
    ) -> Result<RemoteStopResult> {
        self.router.check_open()?;
        // Native custody consumes the permit at each remote-actor stop commit.
        let (authority, request, attribution, permit) = request.into_parts();
        let RemoteRequest::Stop(input) = request else {
            return Err(SeError::invalid(
                "remote stop",
                "an authorized stop request",
            ));
        };
        let custody = self
            .router
            .execution
            .custody
            .get()
            .cloned()
            .ok_or_else(|| {
                SeError::invalid("remote stop", "the destination native process coordinator")
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
        let planned = input.clone();
        let planned_attribution = attribution.clone();
        let plan = store
            .read(admission.clone(), &deadline, move |cx| {
                se_core::remote::plan_stop(authority, planned, &planned_attribution, cx)
            })
            .await?;
        let stopped = custody
            .stop_remote(plan, admission, permit, &deadline)
            .await
            .map_err(|error| {
                super::failure::original_key(error, "remote.stop", &input.idempotency_key)
            })?;
        let witness = match stopped.witness {
            Some(witness) => RemoteStopWitness {
                state: witness.state,
                method: witness.method,
                detail: witness.detail,
            },
            None => RemoteStopWitness {
                state: "unknown".into(),
                method: None,
                detail: Some("native custody returned no stop witness".into()),
            },
        };
        Ok(RemoteStopResult {
            schema: RemoteStopResult::SCHEMA.into(),
            body: RemoteStopBody {
                target: input.target,
                session: input.session,
                idempotency_key: input.idempotency_key,
                result: stopped.result,
                complete: stopped.complete,
                event_id: stopped.event_id,
                witness,
                attribution,
            },
        })
    }
}
