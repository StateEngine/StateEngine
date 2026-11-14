//! Pairing exposes source-address permissions through the protected SSH login.
use super::super::owner_input::SourcePermissionChange;
use super::*;

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
