//! Owner source permissions through protected SSH, with durable completion.
use super::*;
use crate::remote::auth::{Security, VerifiedLocalOwner, refused};
use crate::remote::owner_input::SourcePermissionChange;
use crate::remote::session::control as mutation;
use se_store::remote::{SecurityTransition, SourceContact, SourcePermission};
use se_types::{IdempotencyKey, Read, Result, remote::RemoteAgentAddress};
use sha2::{Digest, Sha256};
use std::sync::Arc;

impl Control {
    pub(super) async fn pairing_permissions(
        &self,
        router: &crate::HostedRouter,
        owner: auth::VerifiedLocalOwner,
        alias: String,
        after: Option<RemoteAgentAddress>,
        change: Option<SourcePermissionChange>,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<serde_json::Value> {
        self.security.owner(&owner)?;
        let records = self.records.clone();
        let config = router
            .execution
            .blocking
            .run_owned(deadline, move || {
                let record = se_core::scope::require_present(
                    records.read(&alias)?,
                    "pairing permissions",
                    "Connect this destination through remote add first.",
                )?;
                record.binding.forward.ok_or_else(|| {
                    SeError::invalid("pairing permissions", "a saved native SSH connection")
                })
            })
            .await?;
        ssh::permissions(
            &config,
            ssh::PermissionsRequest {
                permissions: config.host,
                after,
                change,
            },
        )
        .await
    }

    pub(super) async fn source_permissions(
        &self,
        router: &crate::HostedRouter,
        owner: auth::VerifiedLocalOwner,
        request: ssh::PermissionsRequest,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<serde_json::Value> {
        self.security.owner(&owner)?;
        if request.permissions != self.security.host() {
            return Err(SeError::invalid(
                "pairing permissions",
                "the original saved destination machine identity",
            ));
        }
        let changed = if let Some(change) = request.change {
            let _configure = self.configure.lock().await;
            let expected = change
                .expected_revision
                .map(|value| {
                    std::num::NonZeroU64::new(value)
                        .map(|value| se_store::Revision { value })
                        .ok_or_else(|| SeError::invalid("source permission revision", "nonzero"))
                })
                .transpose()?;
            let result = self
                .security
                .set_source_permission(
                    owner.clone(),
                    session::SetSourcePermission {
                        address: change.address,
                        allowed: change.allowed,
                        expected,
                        key: change.key,
                    },
                )
                .await?;
            Some(
                serde_json::json!({"permission":result.value,"event_id":result.receipt.primary_event,"sockets_pending":result.sockets_pending}),
            )
        } else {
            None
        };
        let security = self.security.clone();
        let (contacts, more) = router
            .execution
            .blocking
            .run_owned(deadline, move || {
                // Each address can contain two 512-byte IDs and appears again
                // in its permission record; keep the entire SSH response below 32 KiB.
                security.list_sources(owner, request.after.as_ref(), 8)
            })
            .await?;
        let next = more
            .then(|| contacts.last().map(|c| c.address.clone()))
            .flatten();
        Ok(serde_json::json!({"sources":contacts,"more":more,"next":next,"changed":changed}))
    }
}

pub struct SetSourcePermission {
    pub address: RemoteAgentAddress,
    pub allowed: bool,
    pub expected: Option<se_store::Revision>,
    pub key: IdempotencyKey,
}

impl Security {
    pub fn list_sources(
        &self,
        owner: VerifiedLocalOwner,
        after: Option<&RemoteAgentAddress>,
        limit: u16,
    ) -> Result<(Vec<SourceContact>, bool)> {
        self.owner(&owner)?;
        self.store
            .read(|phase| phase.remote_source_contacts(after, limit))
    }

    pub async fn set_source_permission(
        self: &Arc<Self>,
        owner: VerifiedLocalOwner,
        request: SetSourcePermission,
    ) -> Result<mutation::ControlReceipt<SourcePermission>> {
        self.owner(&owner)?;
        let security = self.clone();
        // Once this task starts, the socket/IPC waiter cannot cancel the fence
        // and leave an accepted writer completion unobserved. A host crash
        // closes the sockets; the next host reads the durable policy afresh.
        tokio::spawn(async move { security.set_source_owned(owner, request).await })
            .await
            .map_err(|_| refused("source permission completion was lost; inspect its original key using se remote permissions --local in a terminal on the destination"))?
    }

    async fn set_source_owned(
        self: Arc<Self>,
        owner: VerifiedLocalOwner,
        request: SetSourcePermission,
    ) -> Result<mutation::ControlReceipt<SourcePermission>> {
        if let Some(outcome) = self.source_outcome(&request).await? {
            return Ok(outcome);
        }
        let store = self.store.clone();
        let address = request.address.clone();
        let current = self
            .blocking
            .run_owned(&mutation::deadline()?, move || {
                store.read(|p| p.remote_source_permission(&address))
            })
            .await?;
        let previous = match current {
            Read::Present { value } => Some(value.revision),
            Read::Absent { .. } => None,
            _ => {
                return Err(refused(
                    "source permission is unreadable; inspect se remote permissions --local in a terminal on the destination",
                ));
            }
        };
        if previous != request.expected {
            if let Some(outcome) = self.source_outcome(&request).await? {
                return Ok(outcome);
            }
            return Err(refused(
                "source permission changed; run se remote permissions --local in a terminal on the destination before deciding again",
            ));
        }
        if !request.allowed {
            self.source_revoke_intent(&owner, &request).await?;
        }
        let fence = self.source_fence_at(
            &request.address,
            previous.map_or(0, |r| r.value.get()),
            false,
        )?;
        let intent = serde_json::json!({"address":request.address,"allowed":request.allowed,"expected":request.expected});
        let receipt = self
            .store
            .commit(
                se_store::Actor::Human(owner.owner),
                request.key.clone(),
                SecurityTransition::SourcePermission {
                    address: request.address.clone(),
                    allowed: request.allowed,
                    expected: request.expected,
                },
                intent,
            )
            .await?;
        let known = mutation::committed("remote.source.permission", &receipt);
        let value = permission_value(&request)?;
        let store = self.store.clone();
        let address = request.address.clone();
        let current = self
            .blocking
            .run_owned(&mutation::deadline()?, move || {
                se_core::scope::require_present(
                    store.read(|p| p.remote_source_permission(&address))?,
                    "committed source permission",
                    "Inspect this original permission key using se remote permissions --local in a terminal on the destination.",
                )
            })
            .await
            .map_err(|e| known.response_error(e))?;
        if current.revision == value.revision && current.allowed == value.allowed {
            self.source_fence_at(&value.address, value.revision.value.get(), value.allowed)
                .map_err(|e| known.response_error(e))?;
        } else if current.revision.value <= value.revision.value {
            return Err(known.response_error(refused("the committed source permission could not be read back; inspect its original key using se remote permissions --local in a terminal on the destination")));
        }
        let sockets_pending = !mutation::outputs_closed(&[fence])
            .await
            .map_err(|e| known.response_error(e))?;
        Ok(mutation::ControlReceipt {
            value,
            receipt,
            sockets_pending,
        })
    }

    async fn source_outcome(
        &self,
        request: &SetSourcePermission,
    ) -> Result<Option<mutation::ControlReceipt<SourcePermission>>> {
        let store = self.store.clone();
        let key = request.key.clone();
        let outcome = self
            .blocking
            .run_owned(&mutation::deadline()?, move || store.security_outcome(&key))
            .await?;
        let Some((receipt, transition)) = outcome else {
            return Ok(None);
        };
        match transition {
            SecurityTransition::SourcePermission {
                address,
                allowed,
                expected,
            } if address == request.address
                && allowed == request.allowed
                && expected == request.expected => {}
            _ => {
                return Err(refused(
                    "this Owner key belongs to a different source permission intent; retain its original parameters and run se remote permissions --local in a terminal on the destination",
                ));
            }
        }
        // Historical completion does not claim that a later allow/revoke was
        // undone or that every socket from this older action is observed closed.
        Ok(Some(mutation::ControlReceipt {
            value: permission_value(request)?,
            receipt,
            sockets_pending: true,
        }))
    }

    async fn source_revoke_intent(
        &self,
        owner: &VerifiedLocalOwner,
        request: &SetSourcePermission,
    ) -> Result<()> {
        let digest = Sha256::digest(
            serde_json::to_vec(&("remote-source-revoke-intent/v1", &request.key))
                .map_err(|_| refused("source revocation key cannot be encoded"))?,
        );
        let key = IdempotencyKey::new(format!(
            "source-revoke-intent-{}",
            se_types::hex_lower(&digest)
        ))?;
        let transition = SecurityTransition::SourceRevokeIntent {
            address: request.address.clone(),
            expected: request.expected,
            key: request.key.clone(),
        };
        let intent = serde_json::json!({"address":request.address,"expected":request.expected,"key":request.key});
        self.store
            .commit(
                se_store::Actor::Human(owner.owner.clone()),
                key,
                transition,
                intent,
            )
            .await?;
        Ok(())
    }
}

fn permission_value(request: &SetSourcePermission) -> Result<SourcePermission> {
    let revision = request
        .expected
        .map_or(0, |r| r.value.get())
        .checked_add(1)
        .filter(|r| *r <= i64::MAX as u64)
        .and_then(std::num::NonZeroU64::new)
        .ok_or_else(|| refused("source permission revision is exhausted"))?;
    Ok(SourcePermission {
        address: request.address.clone(),
        allowed: request.allowed,
        revision: se_store::Revision { value: revision },
    })
}
