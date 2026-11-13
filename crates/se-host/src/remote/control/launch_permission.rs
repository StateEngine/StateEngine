//! Launch consent is reviewed on the existing protected native pairing channel.
use super::*;
use crate::remote::owner_input::LaunchPermissionChange;

impl Control {
    pub(super) async fn pairing_launch_permissions(
        &self,
        router: &crate::HostedRouter,
        owner: auth::VerifiedLocalOwner,
        alias: String,
        after: Option<RemoteTarget>,
        change: Option<LaunchPermissionChange>,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<serde_json::Value> {
        self.security.owner(&owner)?;
        let records = self.records.clone();
        let (config, grant) = router
            .execution
            .blocking
            .run_owned(deadline, move || {
                let record = se_core::scope::require_present(
                    records.read(&alias)?,
                    "launch pairing permissions",
                    "Connect the destination through remote add first.",
                )?;
                let config = record.binding.forward.ok_or_else(|| {
                    SeError::invalid(
                        "launch pairing permissions",
                        "a saved native SSH connection",
                    )
                })?;
                Ok((config, record.binding.paired.grant))
            })
            .await?;
        ssh::launch_permissions(
            &config,
            ssh::LaunchPermissionsRequest {
                launch_permissions: config.host,
                grant,
                after,
                change,
            },
        )
        .await
    }

    pub(super) async fn launch_permissions(
        &self,
        router: &crate::HostedRouter,
        owner: auth::VerifiedLocalOwner,
        request: ssh::LaunchPermissionsRequest,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<serde_json::Value> {
        self.security.owner(&owner)?;
        if request.launch_permissions != self.security.host() {
            return Err(SeError::invalid(
                "launch pairing permissions",
                "the original saved destination identity",
            ));
        }
        let changed = if let Some(change) = request.change {
            let _configure = self.configure.lock().await;
            let expected = change
                .expected_revision
                .map(|value| {
                    std::num::NonZeroU64::new(value)
                        .map(|value| se_store::Revision { value })
                        .ok_or_else(|| SeError::invalid("launch permission revision", "nonzero"))
                })
                .transpose()?;
            let result = self
                .security
                .set_launch_permission(
                    owner.clone(),
                    change.key,
                    se_store::remote::LaunchPermissionChange {
                        grant: request.grant.clone(),
                        target: change.target,
                        allowed: change.allowed,
                        expected,
                    },
                )
                .await?;
            let state = match result.receipt.state {
                se_store::CommitState::Committed => "committed",
                se_store::CommitState::Replayed | se_store::CommitState::NaturalKeyReplay => {
                    "replayed"
                }
            };
            Some(
                serde_json::json!({"permission":result.value,"event_id":result.receipt.primary_event,"state":state}),
            )
        } else {
            None
        };
        let security = self.security.clone();
        let (targets, more) = router
            .execution
            .blocking
            .run_owned(deadline, move || {
                security.list_launch_candidates(owner, &request.grant, request.after.as_ref())
            })
            .await?;
        let next = more
            .then(|| targets.last().map(|t| t.target.clone()))
            .flatten();
        Ok(serde_json::json!({"targets":targets,"next":next,"more":more,"changed":changed}))
    }
}
