//! Closed per-call scope checks and client dispatch.
use super::*;
impl<B: Budget> RemoteBroker<B> {
    /// Native admission precedes this call; human key selection also requires
    /// the verified current console/ancestry observation.
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
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
        let context = || {
            source.as_ref().map_or_else(
                RemoteCallContext::human_device,
                VerifiedSourceSession::context,
            )
        };
        match operation {
            AnyOp::RemotePrepareSend(input) => {
                let b = self
                    .resolve(&input.host, context(), admission, terminal, deadline)
                    .await?;
                if !b
                    .config
                    .device
                    .scope
                    .allows(RemoteVerb::Send, &input.request.target)
                {
                    return Err(refused("send target or verb is outside this grant"));
                }
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
                self.launch(input, admission, terminal, source.as_ref(), deadline)
                    .await
            }
            AnyOp::RemoteList(input) => {
                let b = self
                    .resolve(&input.host, context(), admission, terminal, deadline)
                    .await?;
                let mut request = input.request;
                scope(
                    &b.config.device.scope,
                    RemoteVerb::List,
                    &mut request.targets,
                )?;
                let call = context();
                call.invocation(&b.config.device, RemoteRequest::List(request.clone()))?;
                let client = self.connection(&b, &call).await?;
                let result = client.list(context(), request.clone()).await?;
                call.check_current()?;
                check_size(&result, request.budget)?;
                if result.schema != RemoteListResult::SCHEMA
                    || result.agents.items().iter().any(|r| {
                        !request.targets.is_empty() && !request.targets.contains(&r.target)
                    })
                {
                    return Err(refused(
                        "remote list returned a mismatched schema or target",
                    ));
                }
                Ok(result.body.into())
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
                        source.as_ref(),
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
                if input.expected_binding.as_ref().is_some_and(|expected| {
                    expected.host != b.config.device.host || expected.grant != b.config.device.grant
                }) {
                    return Err(refused(
                        "saved alias changed host/grant; resolve the original send there with its same key, never retarget it",
                    ));
                }
                let request = input.request;
                if !b
                    .config
                    .device
                    .scope
                    .allows(RemoteVerb::Send, &request.target)
                {
                    return Err(refused("send target or verb is outside this grant"));
                }
                let call = context();
                call.invocation(&b.config.device, RemoteRequest::Send(request.clone()))?;
                let client = self.connection(&b, &call).await?;
                // No retry/re-key here. An already admitted remote send retains
                // its receipt even if the source fence closes while it commits.
                let key = request.idempotency_key.clone();
                let result = client.send(context(), request).await?;
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
                            return Err(refused(
                                "remote receipt changed the original mutation key",
                            ));
                        }
                    }
                    if result.schema != RemoteSendResult::SCHEMA
                        || result.attribution.host != b.config.device.host
                        || result.attribution.grant != b.config.device.grant
                        || result.attribution.device != b.config.device.device
                        || !if matches!(result.receipt, se_types::Receipt::Replayed { .. }) {
                            // A replay carries the original source session/generation,
                            // not the retrying successor. Its lead subject must still
                            // match the same host/project/agent grant binding.
                            result
                                .attribution
                                .source
                                .as_ref()
                                .map(RemoteSourceSession::address)
                                == source.as_ref().map(|s| s.source().address())
                        } else {
                            result.attribution.source.as_ref()
                                == source.as_ref().map(VerifiedSourceSession::source)
                        }
                    {
                        return Err(refused(
                            "remote receipt attribution does not match the original grant/source",
                        ));
                    }
                    result.receipt.validate()?;
                    check_size(&result, REMOTE_FRAME_BYTES as u32)?;
                    Ok(())
                })();
                if let Err(cause) = checked {
                    return Err(SeError::new(se_types::Detail::CommitOutcomeUnknown(
                        se_types::details::CommitOutcomeUnknown {
                            operation: "remote.send".into(),
                            key: Some(key.to_string()),
                            natural_events: vec![],
                        },
                    ))
                    .with_cause(cause));
                }
                Ok(result.body.into())
            }
            _ => Err(refused(
                "only closed remote list/watch/send operations enter this broker",
            )),
        }
    }
}
