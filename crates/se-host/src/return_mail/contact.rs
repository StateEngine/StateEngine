//! Persist the receipt-recovery coordinates before dispatch, without a body copy.
use super::*;
use se_core::ops::Validate;
use sha2::{Digest, Sha256};

impl RemoteBroker {
    pub(crate) async fn prepare_contact(
        self: &Arc<Self>,
        context: &ExecutionContext,
        source: &VerifiedSourceSession,
        input: &mut RemoteSendCall,
        terminal: &HumanTerminal,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<()> {
        input.validate()?;
        let binding = self
            .resolve(
                &input.host,
                source.context(),
                &source_admission(source),
                terminal,
                deadline,
            )
            .await?;
        if !binding
            .device()
            .scope
            .allows(RemoteVerb::Send, &input.request.target)
        {
            return Err(refused(
                "this destination target lacks machine send permission; ask its Owner to review se remote grants, then reconnect using se remote add <ssh-destination> --name <saved-alias> with an authorized machine grant",
            ));
        }
        if input.expected_binding.as_ref().is_some_and(|expected| {
            expected.host != binding.device().host || expected.grant != binding.device().grant
        }) {
            return Err(refused(
                "the saved send binding changed; restore the original pairing before retrying its original key",
            ));
        }
        input.expected_binding = Some(Box::new(RemoteBindingSelection {
            host: binding.device().host,
            grant: binding.device().grant.clone(),
        }));
        let record = PendingContact {
            source: source.source().address(),
            peer: binding.device().host,
            target: input.request.target.clone(),
            alias: input.host.clone(),
            request_key: input.request.idempotency_key.clone(),
            original_grant: binding.device().grant.clone(),
            local_reply: None,
        };
        self.persist_pending(context, source, record).await?;
        // Existing route failures stay visible on resume and do not block this
        // independent send. The durable pending receipt will also be retried.
        let _retained_status = self.start_mail(context, source.clone()).await?;
        Ok(())
    }

    pub(super) async fn persist_pending(
        &self,
        context: &ExecutionContext,
        source: &VerifiedSourceSession,
        record: PendingContact,
    ) -> Result<()> {
        let intent = serde_json::to_value(&record).map_err(|_| poisoned())?;
        let digest = se_types::hex_lower(&Sha256::digest(
            serde_json::to_vec(&record).map_err(|_| poisoned())?,
        ));
        let key = IdempotencyKey::new(format!("remote-contact-pending-{digest}"))?;
        write::commit(
            context,
            source_admission(source),
            key,
            "remote.contact.pending",
            intent,
            vec![se_store::EventBody::RemoteMailboxRecorded {
                change: MailboxChange::Pending { record },
            }],
        )
        .await?;
        context.mail_waits.enable_return_mail();
        Ok(())
    }

    pub(crate) async fn remember_send(
        self: &Arc<Self>,
        context: &ExecutionContext,
        source: &VerifiedSourceSession,
        input: &RemoteSendCall,
        result: &RemoteSendBody,
    ) -> Result<()> {
        let original = match &result.receipt {
            Receipt::Committed { commit } | Receipt::Replayed { original: commit } => {
                commit.value.clone()
            }
            _ => return Ok(()),
        };
        let pending = PendingContact {
            source: source.source().address(),
            peer: result.attribution.host,
            target: input.request.target.clone(),
            alias: input.host.clone(),
            request_key: input.request.idempotency_key.clone(),
            original_grant: result.attribution.grant.clone(),
            local_reply: None,
        };
        self.record_contact(context, source, pending, original)
            .await
    }

    pub(super) async fn record_contact(
        &self,
        context: &ExecutionContext,
        source: &VerifiedSourceSession,
        pending: PendingContact,
        original: se_types::MessageId,
    ) -> Result<()> {
        let _write = self.mailbox.writes.lock().await;
        let lookup = pending.clone();
        let message = original.clone();
        let old = read(context, move |phase| {
            phase.remote_mail_contact(&lookup.source, lookup.peer, &lookup.target, &message)
        })
        .await?;
        if old.as_ref().is_some_and(|c| {
            c.alias == pending.alias
                && c.request_key == pending.request_key
                && c.original_grant == pending.original_grant
        }) {
            return Ok(());
        }
        let lookup = pending.clone();
        let route = read(context, move |phase| {
            phase.remote_mail_route(&lookup.source, lookup.peer, &lookup.target)
        })
        .await?;
        let now = session::now()?;
        let principal = match route {
            Some(route) => route.principal,
            None => RemotePrincipalId::from_parts(
                u64::try_from(now / 1000).map_err(|_| refused("negative return-mail clock"))?,
                session::entropy()?,
            )?,
        };
        let intent = serde_json::json!({"pending":pending,"original":original});
        let digest = se_types::hex_lower(&Sha256::digest(
            serde_json::to_vec(&intent).map_err(|_| poisoned())?,
        ));
        let key = IdempotencyKey::new(format!("remote-contact-{digest}"))?;
        let record = MailContact {
            source: pending.source,
            peer: pending.peer,
            target: pending.target,
            original,
            principal,
            alias: pending.alias,
            request_key: pending.request_key,
            original_grant: pending.original_grant,
            local_reply: pending.local_reply,
        };
        write::commit(
            context,
            source_admission(source),
            key,
            "remote.contact.record",
            intent,
            vec![se_store::EventBody::RemoteMailboxRecorded {
                change: MailboxChange::Contact { record },
            }],
        )
        .await?;
        Ok(())
    }
}
