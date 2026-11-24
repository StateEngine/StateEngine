use super::*;
/// Admit one native Owner call, then route it to its command.
pub(crate) async fn execute(
    router: &crate::HostedRouter,
    call: OwnerCall,
    deadline: &crate::client::lease::Deadline,
) -> Result<crate::OperationOutput> {
    let _work = router.execution.mail_waits.client_work()?;
    let OwnerCall { owner, input } = call;
    input.validate()?;
    router.check_open()?;
    let value = if matches!(&input, OwnerInput::Disable)
        && router.execution.mail_waits.remote_control().is_none()
        && Control::disabled_without_resources(router, &owner, deadline).await?
    {
        policy::disabled()
    } else {
        let (control, owner) =
            Control::prepare(router, owner, input.initializes_resources(), deadline).await?;
        control.dispatch(router, owner, input, deadline).await?
    };
    Ok(crate::OperationOutput {
        schema: "stateengine.remote-control/v1".into(),
        value,
        window: None,
    })
}
impl Control {
    async fn dispatch(
        &self,
        router: &crate::HostedRouter,
        owner: auth::VerifiedLocalOwner,
        input: OwnerInput,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<serde_json::Value> {
        Ok(match input {
            OwnerInput::Authorize(authorization) => {
                serde_json::to_value(self.security.authorize_channel(authorization).await?)
                    .map_err(|_| {
                        SeError::invalid("SSH authorization", "serializable native result")
                    })?
            }
            OwnerInput::Disconnect { alias, forget } => {
                self.disconnect(router, owner, alias, forget, deadline)
                    .await?
            }
            OwnerInput::Add {
                destination,
                alias,
                distribution,
            } => {
                self.add(router, owner, destination, alias, distribution, deadline)
                    .await?
            }
            OwnerInput::PrepareAdd { destination, alias } => {
                let _configure = self.configure.lock().await;
                self.security.owner(&owner)?;
                self.check_add(router, &destination, &alias, deadline)
                    .await?;
                serde_json::json!({"state":"preparing", "name":alias})
            }
            OwnerInput::Bootstrap { source_host } => {
                self.bootstrap(router, owner, source_host, deadline).await?
            }
            OwnerInput::MachineIdentity => {
                let files = self.files.clone();
                let root = router.execution.state_directory.clone();
                let enabled = router
                    .execution
                    .blocking
                    .run_owned(deadline, move || policy::enabled(&*files, &root))
                    .await?;
                serde_json::json!({"host":self.security.host(), "enabled":enabled})
            }
            OwnerInput::PairingLaunchPermissions {
                alias,
                after,
                change,
            } => {
                self.pairing_launch_permissions(router, owner, alias, after, change, deadline)
                    .await?
            }
            OwnerInput::LaunchPermissions(request) => {
                self.launch_permissions(router, owner, request, deadline)
                    .await?
            }
            OwnerInput::PairingPermissions {
                alias,
                after,
                change,
            } => {
                self.pairing_permissions(router, owner, alias, after, change, deadline)
                    .await?
            }
            OwnerInput::SourcePermissions(request) => {
                self.source_permissions(router, owner, request, deadline)
                    .await?
            }
            OwnerInput::LocalPairingPermissions { after, change } => {
                self.source_permissions(
                    router,
                    owner,
                    ssh::PermissionsRequest {
                        permissions: self.security.host(),
                        after,
                        change,
                    },
                    deadline,
                )
                .await?
            }
            OwnerInput::Disable => self.disable(router, owner, deadline).await?,
            OwnerInput::Grants { after, limit } => {
                self.grants(router, owner, after, limit, deadline).await?
            }
            OwnerInput::Revoke {
                grant,
                authority_revision,
                key,
            } => {
                self.revoke(router, owner, grant, authority_revision, key, deadline)
                    .await?
            }
        })
    }
    async fn grants(
        &self,
        router: &crate::HostedRouter,
        owner: auth::VerifiedLocalOwner,
        after: Option<se_types::RemoteGrantId>,
        limit: u16,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<serde_json::Value> {
        let security = self.security.clone();
        let (grants, more) = router
            .execution
            .blocking
            .run_owned(deadline, move || {
                security.list_grants(
                    owner,
                    super::super::session::ListGrants {
                        after,
                        limit: usize::from(limit),
                    },
                )
            })
            .await?;
        Ok(serde_json::json!({"grants":grants,"more":more,"security_notice":self.startup.notice()}))
    }
}
