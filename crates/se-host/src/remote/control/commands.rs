use super::*;
use se_store::Revision;
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(crate) async fn execute(
    router: &crate::HostedRouter,
    call: OwnerCall,
    deadline: &crate::client::lease::Deadline,
) -> Result<crate::OperationOutput> {
    let _work = router.execution.mail_waits.remote_work()?;
    let OwnerCall { owner, input } = call;
    input.validate()?;
    router.check_open()?;
    if matches!(&input, OwnerInput::Disable)
        && router.execution.mail_waits.remote_control().is_none()
        && Control::disabled_without_resources(router, &owner, deadline).await?
    {
        return Ok(crate::OperationOutput {
            schema: "stateengine.remote-control/v1".into(),
            value: serde_json::json!({"state":"disabled","connections_closed":true}),
            window: None,
        });
    }
    let (control, owner) =
        Control::prepare(router, owner, input.initializes_resources(), deadline).await?;
    let value = match input {
        OwnerInput::Authorize(authorization) => {
            serde_json::to_value(control.security.authorize_channel(authorization).await?)
                .map_err(|_| SeError::invalid("SSH authorization", "serializable native result"))?
        }
        OwnerInput::Disconnect { alias, forget } => {
            control
                .disconnect(router, owner, alias, forget, deadline)
                .await?
        }
        OwnerInput::Add {
            destination,
            alias,
            distribution,
        } => {
            control
                .add(router, owner, destination, alias, distribution, deadline)
                .await?
        }
        OwnerInput::PrepareAdd { destination, alias } => {
            let _configure = control.configure.lock().await;
            control.security.owner(&owner)?;
            control
                .check_add(router, &destination, &alias, deadline)
                .await?;
            serde_json::json!({"state":"preparing", "name":alias})
        }
        OwnerInput::Bootstrap { source_host } => {
            control
                .bootstrap(router, owner, source_host, deadline)
                .await?
        }
        OwnerInput::MachineIdentity => {
            let files = control.files.clone();
            let root = router.execution.state_directory.clone();
            let enabled = router
                .execution
                .blocking
                .run_owned(deadline, move || policy::enabled(&*files, &root))
                .await?;
            serde_json::json!({"host":control.security.host(), "enabled":enabled})
        }
        OwnerInput::PairingLaunchPermissions {
            alias,
            after,
            change,
        } => {
            control
                .pairing_launch_permissions(router, owner, alias, after, change, deadline)
                .await?
        }
        OwnerInput::LaunchPermissions(request) => {
            control
                .launch_permissions(router, owner, request, deadline)
                .await?
        }
        OwnerInput::PairingPermissions {
            alias,
            after,
            change,
        } => {
            control
                .pairing_permissions(router, owner, alias, after, change, deadline)
                .await?
        }
        OwnerInput::SourcePermissions(request) => {
            control
                .source_permissions(router, owner, request, deadline)
                .await?
        }
        OwnerInput::LocalPairingPermissions { after, change } => {
            control
                .source_permissions(
                    router,
                    owner,
                    ssh::PermissionsRequest {
                        permissions: control.security.host(),
                        after,
                        change,
                    },
                    deadline,
                )
                .await?
        }
        OwnerInput::Disable => {
            let _configure = control.configure.lock().await;
            control.security.owner(&owner)?;
            control.persist(router, owner, None, deadline).await?;
            control.stop_listener().await?;
            serde_json::json!({"state":"disabled","connections_closed":true})
        }
        OwnerInput::Grants { after, limit } => {
            let security = control.security.clone();
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
            serde_json::json!({"grants":grants,"more":more,"security_notice":control.startup.notice()})
        }
        OwnerInput::Revoke {
            grant,
            authority_revision,
            key,
        } => {
            let _configure = control.configure.lock().await;
            control.security.owner(&owner)?;
            let revision = Revision {
                value: std::num::NonZeroU64::new(authority_revision)
                    .ok_or_else(|| SeError::invalid("grant revision", "nonzero"))?,
            };
            let pending = revocations::Pending {
                grant: grant.clone(),
                authority_revision,
                key: key.clone(),
            };
            // Persist the exact intent before attempting FULL. Cancellation or an
            // unknown result cannot reopen this grant after a host restart.
            control
                .pending_revoke(router, pending.clone(), false, deadline)
                .await?;
            let result = control
                .security
                .revoke(
                    owner,
                    super::super::session::RevokeGrant {
                        grant,
                        expected_revision: revision,
                        key,
                    },
                )
                .await?;
            let known = crate::runtime::CommittedWrite {
                operation: "remote.grant.revoke".into(),
                key: result.receipt.request_key.clone(),
                natural_events: vec![],
                committed_events: result.receipt.events.clone(),
            };
            control
                .pending_revoke(router, pending, true, deadline)
                .await
                .map_err(|error| known.response_error(error))?;
            serde_json::json!({"receipt":receipt(&result.receipt,result.sockets_pending)})
        }
    };
    Ok(crate::OperationOutput {
        schema: "stateengine.remote-control/v1".into(),
        value,
        window: None,
    })
}
fn receipt(receipt: &se_store::CommitReceipt, sockets_pending: bool) -> serde_json::Value {
    serde_json::json!({"state":match receipt.state {se_store::CommitState::Committed=>"committed",_=>"replayed"},"event_id":receipt.primary_event,"idempotency_key":receipt.request_key,"sockets_pending":sockets_pending})
}
