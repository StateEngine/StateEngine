//! Source attribution stays native; launch consent is checked by the destination.
use super::*;
impl<B: Budget> RemoteBroker<B> {
    pub(super) async fn launch(
        &self,
        input: RemoteLaunchCall,
        admission: &Admission,
        terminal: &HumanTerminal,
        source: Option<&VerifiedSourceSession>,
        deadline: &B,
    ) -> Result<AnyOutput> {
        let context = || call_context(source);
        let binding = self
            .resolve(&input.host, context(), admission, terminal, deadline)
            .await?;
        let call = context();
        call.invocation(
            &binding.config.device,
            RemoteRequest::Launch(input.request.clone()),
        )?;
        let client = self.connection(&binding, &call).await?;
        let key = input.request.idempotency_key.clone();
        let result = client.launch(context(), input.request.clone()).await?;
        let checked = (|| {
            let (target, replayed) = started(&result.outcome, &key, "launch")?;
            if result.schema != RemoteLaunchResult::SCHEMA
                || target != &input.request.target
                || !attributed(
                    &result.attribution,
                    &binding.config.device,
                    source,
                    replayed,
                )
            {
                return Err(refused(
                    "remote launch returned a mismatched destination or authenticated source",
                ));
            }
            check_size(&result, REMOTE_FRAME_BYTES as u32)
        })();
        checked.map_err(|cause| outcome_unknown("remote.launch", &key, cause))?;
        Ok(result.body.into())
    }

    /// The worker is a new agent beside the anchor: same project, its own
    /// identity, and a receipt for the original key.
    pub(super) async fn delegate(
        &self,
        input: RemoteDelegateCall,
        admission: &Admission,
        terminal: &HumanTerminal,
        source: Option<&VerifiedSourceSession>,
        deadline: &B,
    ) -> Result<AnyOutput> {
        let context = || call_context(source);
        let binding = self
            .resolve(&input.host, context(), admission, terminal, deadline)
            .await?;
        let call = context();
        call.invocation(
            &binding.config.device,
            RemoteRequest::Delegate(input.request.clone()),
        )?;
        let client = self.connection(&binding, &call).await?;
        let key = input.request.idempotency_key.clone();
        let anchor = &input.request.target;
        let result = client.delegate(context(), input.request.clone()).await?;
        let checked = (|| {
            let (worker, replayed) = started(&result.outcome, &key, "delegation")?;
            if result.schema != RemoteDelegateResult::SCHEMA
                || &result.worker.anchor != anchor
                || worker.project != anchor.project
                || worker.agent == anchor.agent
                || result.worker.ttl_seconds > input.request.ttl_seconds.unwrap_or(u32::MAX)
                || !attributed(
                    &result.attribution,
                    &binding.config.device,
                    source,
                    replayed,
                )
            {
                return Err(refused(
                    "remote delegation returned a mismatched worker, lifetime or authenticated source",
                ));
            }
            check_size(&result, REMOTE_FRAME_BYTES as u32)
        })();
        checked.map_err(|cause| outcome_unknown("remote.delegate", &key, cause))?;
        Ok(result.body.into())
    }
}

/// The started agent and whether its receipt replays the original key.
fn started<'a>(
    outcome: &'a RemoteLaunchOutcome,
    key: &se_types::IdempotencyKey,
    what: &str,
) -> Result<(&'a RemoteTarget, bool)> {
    match outcome {
        RemoteLaunchOutcome::Pending {
            launch,
            idempotency_key,
            ..
        } if idempotency_key == key => Ok((&launch.target, false)),
        RemoteLaunchOutcome::Started { receipt } => {
            receipt.validate()?;
            match receipt {
                se_types::Receipt::Committed { commit } if commit.idempotency_key == *key => {
                    Ok((&commit.value.target, false))
                }
                se_types::Receipt::Replayed { original } if original.idempotency_key == *key => {
                    Ok((&original.value.target, true))
                }
                _ => Err(refused(&format!(
                    "remote started {what} lacks its original committed reservation"
                ))),
            }
        }
        _ => Err(refused(&format!(
            "remote {what} changed the original request key"
        ))),
    }
}
