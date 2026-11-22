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
            let (target, replayed) = match &result.outcome {
                RemoteLaunchOutcome::Pending {
                    launch,
                    idempotency_key,
                    ..
                } if idempotency_key == &key => (&launch.target, false),
                RemoteLaunchOutcome::Started { receipt } => {
                    receipt.validate()?;
                    match receipt {
                        se_types::Receipt::Committed { commit }
                            if commit.idempotency_key == key =>
                        {
                            (&commit.value.target, false)
                        }
                        se_types::Receipt::Replayed { original }
                            if original.idempotency_key == key =>
                        {
                            (&original.value.target, true)
                        }
                        _ => {
                            return Err(refused(
                                "remote started launch lacks its original committed reservation",
                            ));
                        }
                    }
                }
                _ => return Err(refused("remote launch changed the original request key")),
            };
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
}
