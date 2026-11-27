//! Stop authority is the destination's recorded launch; the source only checks echoes.
use super::*;
impl<B: Budget> RemoteBroker<B> {
    pub(super) async fn stop(
        &self,
        input: RemoteStopCall,
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
            RemoteRequest::Stop(input.request.clone()),
        )?;
        let client = self.connection(&binding, &call).await?;
        let key = input.request.idempotency_key.clone();
        let result = client.stop(context(), input.request.clone()).await?;
        let checked = (|| {
            if result.schema != RemoteStopResult::SCHEMA
                || result.target != input.request.target
                || result.session != input.request.session
                || result.idempotency_key != key
                || !attributed(&result.attribution, &binding.config.device, source, false)
            {
                return Err(refused(
                    "remote stop returned a mismatched destination, session, key or authenticated source",
                ));
            }
            check_size(&result, REMOTE_FRAME_BYTES as u32)
        })();
        checked.map_err(|cause| outcome_unknown("remote.stop", &key, cause))?;
        Ok(result.body.into())
    }
}
