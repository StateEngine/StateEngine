//! Each finite route job releases its capacity even when a peer is unavailable.
use super::*;

impl RemoteBroker {
    pub(super) async fn mail_cycle(
        &self,
        context: &ExecutionContext,
        source: &VerifiedSourceSession,
        route: &Route,
    ) -> Result<()> {
        let (binding, client, alias) = self.mail_connection(context, source, route).await?;
        let mut failure = push::page(
            self,
            context,
            source,
            route,
            binding.device(),
            client.clone(),
            &alias,
        )
        .await
        .err();
        let lookup = source.source().address();
        let selected = route.clone();
        let contact = background_read(context, move |p| {
            p.remote_mail_route(&lookup, selected.peer, &selected.target)
        })
        .await?;
        if let Some(contact) = contact {
            let result = receive::page(context, source, &contact, binding.device(), client).await;
            if failure.is_none() {
                failure = result.err();
            }
        }
        failure.map_or(Ok(()), Err)
    }

    pub(super) async fn recover_contact(
        &self,
        context: &ExecutionContext,
        source: &VerifiedSourceSession,
        pending: PendingContact,
    ) -> Result<()> {
        let route = Route {
            peer: pending.peer,
            target: pending.target.clone(),
        };
        let (_, client, _) = self.mail_connection(context, source, &route).await?;
        let result = client
            .resolve_contact(
                source.context(),
                RemoteResolveContact {
                    target: pending.target.clone(),
                    original_grant: pending.original_grant.clone(),
                    idempotency_key: pending.request_key.clone(),
                },
            )
            .await?;
        source.context().check_current()?;
        check_size(&result, 32768)?;
        if result.schema != RemoteContactResult::SCHEMA {
            return Err(refused(
                "send receipt recovery changed its schema; preserve the original send key",
            ));
        }
        match result.body {
            se_types::Read::Present { value }
                if value.source == pending.source
                    && value.target == pending.target
                    && value.original_grant == pending.original_grant
                    && value.idempotency_key == pending.request_key =>
            {
                self.record_contact(context, source, pending, value.message)
                    .await
            }
            se_types::Read::Absent { .. } => Ok(()),
            _ => Err(refused(
                "send receipt recovery returned an unreadable or mismatched source contact; preserve the original send key",
            )),
        }
    }

    async fn mail_connection(
        &self,
        context: &ExecutionContext,
        source: &VerifiedSourceSession,
        route: &Route,
    ) -> Result<(Binding, Arc<dyn RemoteClient>, String)> {
        let lookup = source.source().address();
        let selected = route.clone();
        let alias = background_read(context, move |p| {
            p.remote_mail_alias(&lookup, selected.peer, &selected.target)
        })
        .await?
        .ok_or_else(|| {
            refused("this return-mail route has no retained source intent or contact")
        })?;
        let terminal = HumanTerminal::Refused {
            reason: "a native source agent session, never human authority".into(),
        };
        let binding = self
            .resolve(
                &alias,
                source.context(),
                &source_admission(source),
                &terminal,
                &session::control::deadline()?,
            )
            .await?;
        if binding.device().host != route.peer {
            return Err(refused(
                "the return-mail alias changed machine; restore the original destination through pairing",
            ));
        }
        let client = self.connection(&binding, &source.context()).await?;
        Ok((binding, client, alias))
    }
}
