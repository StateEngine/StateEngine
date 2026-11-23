//! Closed per-call scope checks and client dispatch.
use super::*;
impl<B: Budget> RemoteBroker<B> {
    /// Native admission precedes this call; human key selection also requires
    /// the verified current console/ancestry observation.
    pub async fn execute(
        &self,
        operation: AnyOp,
        admission: &Admission,
        terminal: &HumanTerminal,
        source: Option<VerifiedSourceSession>,
        deadline: &B,
    ) -> Result<AnyOutput> {
        operation.validate()?;
        se_core::admission::authorize(operation.meta(), admission)?;
        match &admission.actor {
            Actor::Agent(_) if source.is_none() => {
                return Err(refused("no verified source session; never use a human key"));
            }
            Actor::Remote(_) => {
                return Err(refused(
                    "remote device authority cannot become a local source broker principal",
                ));
            }
            Actor::Human(_) if source.is_some() => {
                return Err(refused("human/source context disagreement"));
            }
            _ => (),
        }
        let source = source.as_ref();
        let context = || call_context(source);
        match operation {
            AnyOp::RemotePrepareSend(input) => {
                let b = self
                    .resolve(&input.host, context(), admission, terminal, deadline)
                    .await?;
                allow_send(&b.config.device.scope, &input.request.target)?;
                context()
                    .invocation(&b.config.device, RemoteRequest::Send(input.request.clone()))?;
                Ok(RemoteSendPreparation {
                    host: b.config.device.host,
                    grant: b.config.device.grant.clone(),
                    target: input.request.target,
                    session: input.request.session,
                    idempotency_key: input.request.idempotency_key,
                    body_bytes: input.request.body.len() as u32,
                }
                .into())
            }
            AnyOp::RemoteLaunch(input) => {
                self.launch(input, admission, terminal, source, deadline)
                    .await
            }
            AnyOp::RemoteList(input) => {
                let b = self
                    .resolve(&input.host, context(), admission, terminal, deadline)
                    .await?;
                self.list(input, &b, source).await
            }
            AnyOp::RemoteWatch(input) => {
                let b = self
                    .resolve(&input.host, context(), admission, terminal, deadline)
                    .await?;
                let mut request = input.request;
                scope(
                    &b.config.device.scope,
                    RemoteVerb::Watch,
                    &mut request.targets,
                )?;
                request.validate()?;
                let call = context();
                call.invocation(&b.config.device, RemoteRequest::Watch(request.clone()))?;
                let client = self.connection(&b, &call).await?;
                let result = self
                    .watches
                    .read(
                        &b.config.device,
                        source,
                        client,
                        (request, input.reader_id),
                        input.wait_ms,
                        deadline,
                    )
                    .await?;
                call.check_current()?;
                Ok(result.body.into())
            }
            AnyOp::RemoteSend(input) => {
                let b = self
                    .resolve(&input.host, context(), admission, terminal, deadline)
                    .await?;
                self.send(input, &b, source).await
            }
            _ => Err(refused(
                "only closed remote list/watch/send operations enter this broker",
            )),
        }
    }
    async fn list(
        &self,
        input: RemoteListCall,
        b: &Binding,
        source: Option<&VerifiedSourceSession>,
    ) -> Result<AnyOutput> {
        let mut request = input.request;
        scope(
            &b.config.device.scope,
            RemoteVerb::List,
            &mut request.targets,
        )?;
        let call = call_context(source);
        call.invocation(&b.config.device, RemoteRequest::List(request.clone()))?;
        let client = self.connection(b, &call).await?;
        let result = client.list(call_context(source), request.clone()).await?;
        call.check_current()?;
        check_size(&result, request.budget)?;
        if result.schema != RemoteListResult::SCHEMA
            || result
                .agents
                .items()
                .iter()
                .any(|r| !request.targets.is_empty() && !request.targets.contains(&r.target))
        {
            return Err(refused(
                "remote list returned a mismatched schema or target",
            ));
        }
        Ok(result.body.into())
    }
    async fn send(
        &self,
        input: RemoteSendCall,
        b: &Binding,
        source: Option<&VerifiedSourceSession>,
    ) -> Result<AnyOutput> {
        let device = &b.config.device;
        if input
            .expected_binding
            .as_ref()
            .is_some_and(|expected| expected.host != device.host || expected.grant != device.grant)
        {
            return Err(refused(
                "saved alias changed host/grant; resolve the original send there with its same key, never retarget it",
            ));
        }
        let request = input.request;
        allow_send(&device.scope, &request.target)?;
        let call = call_context(source);
        call.invocation(device, RemoteRequest::Send(request.clone()))?;
        let client = self.connection(b, &call).await?;
        // No retry/re-key here. An already admitted remote send retains
        // its receipt even if the source fence closes while it commits.
        let key = request.idempotency_key.clone();
        let result = client.send(call_context(source), request).await?;
        let checked = (|| {
            match &result.receipt {
                se_types::Receipt::Committed { commit }
                | se_types::Receipt::Replayed { original: commit }
                    if commit.idempotency_key == key => {}
                se_types::Receipt::Pending {
                    idempotency_key, ..
                } if *idempotency_key == key => (),
                se_types::Receipt::Refused { .. } => (),
                _ => {
                    return Err(refused("remote receipt changed the original mutation key"));
                }
            }
            let replayed = matches!(result.receipt, se_types::Receipt::Replayed { .. });
            if result.schema != RemoteSendResult::SCHEMA
                || !attributed(&result.attribution, device, source, replayed)
            {
                return Err(refused(
                    "remote receipt attribution does not match the original grant/source",
                ));
            }
            result.receipt.validate()?;
            check_size(&result, REMOTE_FRAME_BYTES as u32)
        })();
        checked.map_err(|cause| outcome_unknown("remote.send", &key, cause))?;
        Ok(result.body.into())
    }
}
