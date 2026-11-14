//! Continue the conversation through the existing source-to-destination link.
use super::*;

pub(super) async fn page(
    broker: &RemoteBroker,
    context: &ExecutionContext,
    source: &VerifiedSourceSession,
    route: &Route,
    device: &MachineSession,
    client: Arc<dyn RemoteClient>,
    alias: &str,
) -> Result<()> {
    let address = source.source().address();
    let peer = RemoteAgentAddress {
        host: route.peer,
        project: route.target.project.clone(),
        agent: route.target.agent.clone(),
    };
    let lookup = address.clone();
    let outgoing = background_read(context, move |phase| {
        phase.remote_outgoing_replies(&lookup, &peer, 20)
    })
    .await?;
    let mut failure = None;
    for outgoing in outgoing {
        let result=async {
            let key=IdempotencyKey::new(format!("remote-reply-{}",outgoing.message))?;
            let pending=PendingContact { source:address.clone(),peer:route.peer,target:route.target.clone(),alias:alias.into(),
                request_key:key.clone(),original_grant:device.grant.clone(),local_reply:Some(outgoing.message.clone()) };
            broker.persist_pending(context,source,pending.clone()).await?;
            let result=client.reply(source.context(),RemoteSendReply {
                source_message:outgoing.message,target:route.target.clone(),reply_to:outgoing.original,body:outgoing.body,
                idempotency_key:key.clone(),kind:outgoing.kind,quiet:outgoing.quiet,
            }).await?;
            source.context().check_current()?;
            check_size(&result,65536)?;
            result.receipt.validate()?;
            let (commit,replayed)=match &result.receipt {
                Receipt::Committed { commit }=>(commit,false),
                Receipt::Replayed { original }=>(original,true),
                _=>return Err(refused("remote reply has no committed receipt; its saved source mail and original key remain pending")),
            };
            if result.schema != RemoteSendResult::SCHEMA || commit.idempotency_key != key
                || result.attribution.host != device.host || result.attribution.grant != device.grant || result.attribution.device != device.device
                || if replayed { result.attribution.source.as_ref().map(RemoteSourceSession::address) != Some(address.clone()) }
                    else { result.attribution.source.as_ref()!=Some(source.source()) } {
                return Err(refused("remote reply receipt differs from its original machine, source or mutation key; retain the pending mail"));
            }
            broker.record_contact(context,source,pending,commit.value.clone()).await
        }.await;
        if let Err(error) = result
            && failure.is_none()
        {
            failure = Some(error);
        }
    }
    failure.map_or(Ok(()), Err)
}
