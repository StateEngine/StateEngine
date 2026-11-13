//! Owner target consent does not stop an already admitted or running lifecycle.
use super::*;
use crate::remote::auth::{Security, VerifiedLocalOwner, refused};
use se_store::remote::{
    LaunchCandidate, LaunchPermission, LaunchPermissionChange, SecurityTransition,
};
use se_types::{IdempotencyKey, Result, remote::*};

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
                    "Inspect the original change key through pairing permissions.",
                )
            })
            .await
            .map_err(|e| known.response_error(e))?;
        if current.revision.value < value.revision.value
            || (current.revision == value.revision && current.allowed != value.allowed)
        {
            return Err(known.response_error(refused("committed launch consent differs from its read-back; inspect its original key through pairing permissions")));
        }
        Ok(control::ControlReceipt {
            value,
            receipt,
            sockets_pending: false,
        })
    }
}
