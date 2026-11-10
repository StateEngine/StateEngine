//! Finite native Owner controls over the existing FULL writer.
use crate::remote::{
    auth::{Security, VerifiedLocalOwner, refused},
    *,
};
use se_store::{Actor, CommitReceipt, remote::*};
use se_types::{IdempotencyKey, Result};

pub struct RevokeGrant {
    pub grant: RemoteGrantId,
    pub expected_revision: se_store::Revision,
    pub key: IdempotencyKey,
}
pub struct ListGrants {
    pub after: Option<RemoteGrantId>,
    pub limit: usize,
}
pub struct ControlReceipt<T> {
    pub value: T,
    pub receipt: CommitReceipt,
    pub sockets_pending: bool,
}
impl Security {
    pub(crate) fn owner(&self, owner: &VerifiedLocalOwner) -> Result<()> {
        if owner.owner != self.store.owner
            || owner.generation != self.store.generation
            || owner.deadline <= std::time::Instant::now()
        {
            return Err(refused(
                "native Owner admission is stale or belongs to another runtime",
            ));
        }
        Ok(())
    }
    /// Native credential/host-identity rotation calls this before replacing its key.
    /// This instance remains fenced even on failure/unknown; restart only after
    /// resolving the original key and completing the native rotation.
    pub async fn revoke_all(
        &self,
        owner: VerifiedLocalOwner,
        key: IdempotencyKey,
    ) -> Result<ControlReceipt<()>> {
        self.owner(&owner)?;
        self.revoke_all_before_listen(key).await
    }
    /// Automatic invalidation by the owning host before exposing a changed
    /// protected credential/store binding. This grants no Owner capability.
    pub(crate) async fn revoke_all_before_listen(
        &self,
        key: IdempotencyKey,
    ) -> Result<ControlReceipt<()>> {
        let fences = self.fence_all()?;
        for fence in &fences {
            fence.revoke()?;
        }
        let receipt = self
            .store
            .commit(
                Actor::Human(self.store.owner.clone()),
                key,
                SecurityTransition::RevokeAll,
                serde_json::json!({"host":self.host,"store":self.store.info.id}),
            )
            .await?;
        let known = committed("remote.grants.revoke-all", &receipt);
        let closed = outputs_closed(&fences)
            .await
            .map_err(|error| known.response_error(error))?;
        Ok(ControlReceipt {
            value: (),
            receipt,
            sockets_pending: !closed,
        })
    }
    pub fn list_grants(
        &self,
        owner: VerifiedLocalOwner,
        request: ListGrants,
    ) -> Result<(Vec<GrantRecord>, bool)> {
        self.owner(&owner)?;
        self.store.grants(request.after.as_ref(), request.limit)
    }
    pub async fn revoke(
        &self,
        owner: VerifiedLocalOwner,
        request: RevokeGrant,
    ) -> Result<ControlReceipt<RemoteGrantId>> {
        self.owner(&owner)?;
        let store = self.store.clone();
        let id = request.grant.clone();
        let grant = self
            .blocking
            .run(
                crate::runtime::BlockingClass::Foreground,
                &deadline()?,
                move || store.grant(&id),
            )
            .await?;
        let fence = self.fence(&grant)?;
        fence.revoke()?;
        let intent = serde_json::json!({"grant":request.grant,"expected_revision":request.expected_revision});
        let receipt = self
            .store
            .commit(
                Actor::Human(owner.owner),
                request.key,
                SecurityTransition::Revoke {
                    grant: request.grant.clone(),
                    expected: request.expected_revision,
                },
                intent,
            )
            .await?;
        // Disconnection completion is read outside the finite enqueue/revoke mutex.
        let known = committed("remote.grant.revoke", &receipt);
        let sockets_pending = !outputs_closed(std::slice::from_ref(&fence))
            .await
            .map_err(|error| known.response_error(error))?;
        if !sockets_pending {
            self.retire_fence(&request.grant, &fence)
                .map_err(|error| known.response_error(error))?;
        }
        Ok(ControlReceipt {
            value: request.grant,
            receipt,
            sockets_pending,
        })
    }
}
pub(crate) fn deadline() -> Result<crate::client::lease::Deadline> {
    crate::client::lease::Deadline::from_options(&crate::client::ClientOptions {
        expected_generation: None,
        timeout: std::time::Duration::from_secs(30),
        cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    })
}

pub(super) fn committed(
    operation: &str,
    receipt: &CommitReceipt,
) -> crate::runtime::CommittedWrite {
    crate::runtime::CommittedWrite {
        operation: operation.into(),
        key: receipt.request_key.clone(),
        natural_events: vec![],
        committed_events: receipt.events.clone(),
    }
}
async fn outputs_closed(
    fences: &[std::sync::Arc<crate::remote::auth::GrantFence>],
) -> Result<bool> {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(1);
    loop {
        let closed = fences
            .iter()
            .map(|fence| fence.outputs_closed())
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .all(|closed| closed);
        if closed || std::time::Instant::now() >= until {
            return Ok(closed);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
