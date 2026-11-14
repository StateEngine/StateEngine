//! Durable Owner consent changes and their native writer read-back.
use super::control;
use crate::remote::auth::{Security, VerifiedLocalOwner, refused};
use se_store::remote::{
    LaunchCandidate, LaunchPermission, LaunchPermissionChange, SecurityTransition, SourceContact,
    SourcePermission,
};
use se_types::{IdempotencyKey, Read, Result, remote::*};
use sha2::{Digest, Sha256};
use std::sync::Arc;

impl Security {
    pub fn list_launch_candidates(
        &self,
        owner: VerifiedLocalOwner,
        grant: &RemoteGrantId,
        after: Option<&RemoteTarget>,
    ) -> Result<(Vec<LaunchCandidate>, bool)> {
        self.owner(&owner)?;
        self.store
            .read(|phase| phase.remote_launch_candidates(grant, after, 4))
    }

    pub async fn set_launch_permission(
        &self,
        owner: VerifiedLocalOwner,
        key: IdempotencyKey,
        change: LaunchPermissionChange,
    ) -> Result<control::ControlReceipt<LaunchPermission>> {
        self.owner(&owner)?;
        let revision = change
            .expected
            .map_or(0, |r| r.value.get())
            .checked_add(1)
            .filter(|r| *r <= i64::MAX as u64)
            .and_then(std::num::NonZeroU64::new)
            .ok_or_else(|| {
                refused(
                    "launch permission revision exhausted; preserve its original Owner request key",
                )
            })?;
        let value = LaunchPermission {
            grant: change.grant.clone(),
            target: change.target.clone(),
            allowed: change.allowed,
            revision: se_store::Revision { value: revision },
        };
        let intent = serde_json::to_value(&change)
            .map_err(|_| refused("launch permission intent cannot be encoded"))?;
        let receipt = self
            .store
            .commit(
                se_store::Actor::Human(owner.owner),
                key,
                SecurityTransition::LaunchPermission { change },
                intent,
            )
            .await?;
        let known = control::committed("remote.launch.permission", &receipt);
        let store = self.store.clone();
        let recorded = value.clone();
        let current = self
            .blocking
            .run_owned(&control::deadline()?, move || {
                se_core::scope::require_present(
                    store
                        .read(|p| p.remote_launch_permission(&recorded.grant, &recorded.target))?,
                    "committed launch permission",
                    "Inspect the original change key with se remote permissions --name <saved-alias> --launch in a terminal.",
                )
            })
            .await
            .map_err(|e| known.response_error(e))?;
        if current.revision.value < value.revision.value
            || (current.revision == value.revision && current.allowed != value.allowed)
        {
            return Err(known.response_error(refused("committed launch consent differs from its read-back; inspect its original key with se remote permissions --name <saved-alias> --launch in a terminal")));
        }
        Ok(control::ControlReceipt {
            value,
            receipt,
            sockets_pending: false,
        })
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
    ) -> Result<control::ControlReceipt<SourcePermission>> {
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
    ) -> Result<control::ControlReceipt<SourcePermission>> {
        if let Some(outcome) = self.source_outcome(&request).await? {
            return Ok(outcome);
        }
        let store = self.store.clone();
        let address = request.address.clone();
        let current = self
            .blocking
            .run_owned(&control::deadline()?, move || {
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
        let known = control::committed("remote.source.permission", &receipt);
        let value = permission_value(&request)?;
        let store = self.store.clone();
        let address = request.address.clone();
        let current = self
            .blocking
            .run_owned(&control::deadline()?, move || {
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
        let sockets_pending = !control::outputs_closed(&[fence])
            .await
            .map_err(|e| known.response_error(e))?;
        Ok(control::ControlReceipt {
            value,
            receipt,
            sockets_pending,
        })
    }

    async fn source_outcome(
        &self,
        request: &SetSourcePermission,
    ) -> Result<Option<control::ControlReceipt<SourcePermission>>> {
        let store = self.store.clone();
        let key = request.key.clone();
        let outcome = self
            .blocking
            .run_owned(&control::deadline()?, move || store.security_outcome(&key))
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
        Ok(Some(control::ControlReceipt {
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
