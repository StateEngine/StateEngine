//! Native admission for external seat claims, external session capabilities,
//! and out-of-band Owner external-seat controls.
use super::*;
use crate::external::{
    EXTERNAL_SESSION_CAPABILITY, ExternalClaimBootstrap, ExternalRequest, PendingClaimHandle,
    lifecycle::resolve_external_agent, wait::WaitPrincipal,
};
use se_store::{EventBody, SessionSurface, Snapshot};
use se_types::{AgentId, ProjectId, Result, SeError, SessionId};
use std::sync::Arc;

/// Admitted external IPC request ready for async execution in `serve.rs`.
pub(crate) enum ExternalCall {
    ClaimOpen {
        handle: PendingClaimHandle,
    },
    ClaimWait {
        claim_id: String,
        peer_binding: Vec<u8>,
        connection_nonce: [u8; 32],
    },
    List {
        project: Option<ProjectId>,
    },
    Approve {
        claim_id: String,
    },
    Revoke {
        project: ProjectId,
        agent: String,
    },
    MailWait {
        principal: WaitPrincipal,
        after: Option<String>,
        timeout_ms: u64,
    },
}

impl AdmissionContext {
    pub(super) fn external_caller(
        &self,
        phase: &se_store::ReadPhase,
        connection: &PresentedAuthority,
        override_authority: Option<&PresentedAuthority>,
    ) -> Option<Result<(Admission, HumanTerminal)>> {
        if matches!(
            connection,
            PresentedAuthority::ExternalSession(_) | PresentedAuthority::ExternalClaim(_)
        ) && override_authority.is_some()
        {
            return Some(Err(SeError::invalid(
                "external seat connection",
                "one immutable seat per connection without in-band identity switching",
            )));
        }
        match (override_authority, connection) {
            (Some(PresentedAuthority::ExternalSession(secret)), _)
            | (None, PresentedAuthority::ExternalSession(secret)) => {
                Some(self.external_session(phase, secret).map(|admission| {
                    (
                        admission,
                        HumanTerminal::Refused {
                            reason: "external seat authority cannot become an owner terminal"
                                .into(),
                        },
                    )
                }))
            }
            (None, PresentedAuthority::ExternalClaim(_)) => Some(Err(SeError::invalid(
                "external claim",
                "out-of-band Owner approval (`se external approve <claim-id>`) before running operations",
            ))),
            _ => None,
        }
    }

    /// Authenticate a dedicated stdio MCP bridge opening a pending external claim.
    /// Verifies same OS account, installed executable image, current host generation,
    /// registered project, and external-eligible agent.
    pub(crate) fn external_claim_handshake(
        &self,
        peer: &PeerProof,
        claim: &ExternalClaimBootstrap,
    ) -> Result<ConnectionGrant> {
        claim.validate()?;
        let local = se_proc::native_ipc::observe_ipc_self().map_err(|error| {
            se_core::scope::unreadable("native host identity", &error.to_string())
        })?;
        if peer.native().principal() != local.principal() {
            return Err(SeError::invalid(
                "external seat bridge",
                "the same native OS account as the host",
            ));
        }
        if peer.native().image_sha256() != self.image_sha256 {
            return Err(SeError::invalid(
                "external seat bridge",
                "the installed StateEngine executable",
            ));
        }
        let project = match &claim.project {
            Some(project) => project.clone(),
            None => {
                let cwd = std::fs::canonicalize(claim.cwd.to_local()?).map_err(|error| {
                    se_core::scope::unreadable("current directory", &error.to_string())
                })?;
                self.guest_project(&cwd)?
            }
        };
        let phase = self.reads.read_phase().map_err(|e| store_error(&e))?;
        if let Err(error) = self.check_generation(&phase) {
            return crate::runtime::executor::close_read(Err(error), phase.close());
        }
        let (agent_id, agent_name, _) = resolve_external_agent(
            phase,
            &project,
            &self.owner,
            self.generation.get(),
            &claim.agent,
            true,
        )?;
        let now_us = super::super::start::now_unix_micros()?;
        let bridge = Arc::new(std::sync::Mutex::new(BridgeBinding::default()));
        let handle = self
            .external
            .open_claim(crate::external::registry::NewClaim {
                project_id: project,
                agent_id,
                agent_name,
                peer_binding: peer.native().binding(),
                peer_pid: peer.native().pid(),
                connection_nonce: claim.connection_nonce,
                host_generation: self.generation,
                now_us,
                bridge: Arc::clone(&bridge),
            })?;
        Ok(ConnectionGrant {
            owner_key: None,
            guest: None,
            external_claim: Some(handle),
            external_active: bridge,
        })
    }

    /// Authenticate an active external seat capability and verify host-generation binding.
    pub(crate) fn external_session(
        &self,
        phase: &se_store::ReadPhase,
        secret: &se_types::Secret,
    ) -> Result<Admission> {
        let admission = self.credential(phase, secret, EXTERNAL_SESSION_CAPABILITY)?;
        let session_id = admission
            .session
            .clone()
            .ok_or_else(|| SeError::invalid("external seat", "an active session ID"))?;
        let verify_phase = self.reads.read_phase().map_err(|e| store_error(&e))?;
        let mut snap = verify_phase
            .into_snapshot(se_core::admission::read_scope(&admission))
            .map_err(|e| store_error(&e))?;
        let checked = (|| {
            let rec = se_core::scope::require_present(
                snap.session(session_id).map_err(|e| store_error(&e))?,
                "external seat session",
                "Reconnect your external bridge and re-approve with `se external approve`.",
            )?;
            let orig = rec.original.as_deref().unwrap_or(&rec.current);
            let EventBody::SessionPrepared {
                surface: Some(SessionSurface::External),
                generation,
                ..
            } = &orig.body
            else {
                return Err(SeError::invalid(
                    "external seat session",
                    "a session prepared for an external seat",
                ));
            };
            if *generation != self.generation.get() {
                return Err(SeError::new(se_types::Detail::CapabilityInvalid(
                    se_types::details::CapabilityInvalid {
                        subject: "external seat".into(),
                        reason: "host restarted since this external seat was approved".into(),
                        next_step: "Reconnect your external bridge (`se mcp --as <agent>`) and approve the new claim with `se external approve <claim-id>`.".into(),
                    },
                )));
            }
            if !matches!(rec.current.body, EventBody::SessionActivated { .. }) {
                return Err(SeError::new(se_types::Detail::CapabilityInvalid(
                    se_types::details::CapabilityInvalid {
                        subject: "external seat".into(),
                        reason: "external seat is no longer active".into(),
                        next_step: "Reconnect your external bridge and approve a fresh claim."
                            .into(),
                    },
                )));
            }
            Ok(())
        })();
        crate::runtime::executor::close_read(checked, snap.close())?;
        Ok(admission)
    }

    /// Admit an `IpcRequest::External` frame under strict per-variant authority rules.
    pub(crate) fn admit_external(
        &self,
        peer: &PeerProof,
        connection: &PresentedAuthority,
        override_authority: Option<&PresentedAuthority>,
        grant: &ConnectionGrant,
        presence: Option<&crate::client::presence::OwnerPresence>,
        request: ExternalRequest,
    ) -> Result<ExternalCall> {
        request.validate()?;
        let mut phase = self.reads.read_phase().map_err(|e| store_error(&e))?;
        let res = (|| {
            self.check_generation(&phase)?;
            match request {
                ExternalRequest::ClaimOpen => {
                    self.admit_claim_open(peer, connection, override_authority, grant)
                }
                ExternalRequest::ClaimWait { claim_id } => {
                    self.admit_claim_wait(peer, connection, override_authority, grant, claim_id)
                }
                ExternalRequest::List { project } => {
                    self.require_external_owner(
                        &mut phase,
                        peer,
                        connection,
                        override_authority,
                        grant,
                        presence,
                        "external.list",
                    )?;
                    Ok(ExternalCall::List { project })
                }
                ExternalRequest::Approve { claim_id } => {
                    self.require_external_owner(
                        &mut phase,
                        peer,
                        connection,
                        override_authority,
                        grant,
                        presence,
                        "external.approve",
                    )?;
                    Ok(ExternalCall::Approve { claim_id })
                }
                ExternalRequest::Revoke { project, agent } => {
                    self.require_external_owner(
                        &mut phase,
                        peer,
                        connection,
                        override_authority,
                        grant,
                        presence,
                        "external.revoke",
                    )?;
                    let project = project.ok_or_else(|| {
                        SeError::new(se_types::Detail::ProjectRequired(
                            se_types::details::ProjectRequired { choices: vec![] },
                        ))
                    })?;
                    Ok(ExternalCall::Revoke { project, agent })
                }
                ExternalRequest::MailWait {
                    project,
                    agent,
                    after,
                    timeout_ms,
                } => self.admit_mail_wait(
                    &mut phase,
                    peer,
                    connection,
                    override_authority,
                    grant,
                    presence,
                    project,
                    agent,
                    after,
                    timeout_ms,
                ),
            }
        })();
        crate::runtime::executor::close_read(res, phase.close())
    }

    fn admit_claim_open(
        &self,
        peer: &PeerProof,
        connection: &PresentedAuthority,
        override_authority: Option<&PresentedAuthority>,
        grant: &ConnectionGrant,
    ) -> Result<ExternalCall> {
        if override_authority.is_some()
            || !matches!(connection, PresentedAuthority::ExternalClaim(_))
        {
            return Err(SeError::invalid(
                "external claim open",
                "the bridge connection that opened this pending claim",
            ));
        }
        let handle = grant.external_claim.clone().ok_or_else(|| {
            SeError::invalid(
                "external claim",
                "an active pending claim on this connection",
            )
        })?;
        if handle.peer_binding != peer.native().binding()
            || handle.host_generation != self.generation
        {
            return Err(SeError::invalid(
                "external claim peer",
                "the exact bridge process and host generation that opened this claim",
            ));
        }
        Ok(ExternalCall::ClaimOpen { handle })
    }

    fn admit_claim_wait(
        &self,
        peer: &PeerProof,
        connection: &PresentedAuthority,
        override_authority: Option<&PresentedAuthority>,
        grant: &ConnectionGrant,
        claim_id: String,
    ) -> Result<ExternalCall> {
        if override_authority.is_some()
            || !matches!(connection, PresentedAuthority::ExternalClaim(_))
        {
            return Err(SeError::invalid(
                "external claim wait",
                "the bridge connection that opened this pending claim",
            ));
        }
        let handle = grant.external_claim.as_ref().ok_or_else(|| {
            SeError::invalid(
                "external claim",
                "an active pending claim on this connection",
            )
        })?;
        if handle.claim_id != claim_id || handle.peer_binding != peer.native().binding() {
            return Err(SeError::invalid(
                "external claim binding",
                "the exact claim ID and bridge process bound to this connection",
            ));
        }
        Ok(ExternalCall::ClaimWait {
            claim_id,
            peer_binding: handle.peer_binding.clone(),
            connection_nonce: handle.connection_nonce,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_mail_wait(
        &self,
        phase: &mut se_store::ReadPhase,
        peer: &PeerProof,
        connection: &PresentedAuthority,
        override_authority: Option<&PresentedAuthority>,
        grant: &ConnectionGrant,
        presence: Option<&crate::client::presence::OwnerPresence>,
        project: Option<ProjectId>,
        agent: Option<String>,
        after: Option<String>,
        timeout_ms: Option<u64>,
    ) -> Result<ExternalCall> {
        if matches!(
            connection,
            PresentedAuthority::ExternalSession(_) | PresentedAuthority::ExternalClaim(_)
        ) && override_authority.is_some()
        {
            return Err(SeError::invalid(
                "external seat connection",
                "one immutable seat per connection without in-band identity switching",
            ));
        }
        let timeout_ms = timeout_ms.unwrap_or(crate::external::DEFAULT_WAIT_TIMEOUT_MS);
        let effective = override_authority.unwrap_or(connection);
        match effective {
            PresentedAuthority::ExternalSession(secret) => {
                let secret = Arc::new(se_types::Secret::new(secret.expose().to_vec())?);
                let admission = self.external_session(phase, &secret)?;
                check_bound_project(&admission, project.as_ref())?;
                Ok(ExternalCall::MailWait {
                    principal: WaitPrincipal::Credential {
                        secret,
                        purpose: EXTERNAL_SESSION_CAPABILITY,
                    },
                    after,
                    timeout_ms,
                })
            }
            PresentedAuthority::Session(secret) => {
                let secret = Arc::new(se_types::Secret::new(secret.expose().to_vec())?);
                let admission = self.session(phase, &secret)?;
                check_bound_project(&admission, project.as_ref())?;
                Ok(ExternalCall::MailWait {
                    principal: WaitPrincipal::Credential {
                        secret,
                        purpose: SESSION_CAPABILITY,
                    },
                    after,
                    timeout_ms,
                })
            }
            PresentedAuthority::OwnerProof { .. } => {
                let (admission, _) =
                    self.caller(phase, peer, connection, override_authority, grant, presence)?;
                if !matches!(admission.actor, Actor::Human(_)) {
                    return Err(SeError::new(se_types::Detail::OwnerRequired(
                        se_types::details::OwnerRequired {
                            op: "msg.wait".into(),
                        },
                    )));
                }
                let project = project.ok_or_else(|| {
                    SeError::new(se_types::Detail::ProjectRequired(
                        se_types::details::ProjectRequired { choices: vec![] },
                    ))
                })?;
                let selector = agent.ok_or_else(|| {
                    SeError::invalid(
                        "mail wait target",
                        "`--as <agent>` specifying the active external seat to wait on",
                    )
                })?;
                let resolve_phase = self.reads.read_phase().map_err(|e| store_error(&e))?;
                let (agent_id, _, _) = resolve_external_agent(
                    resolve_phase,
                    &project,
                    &self.owner,
                    self.generation.get(),
                    &selector,
                    false,
                )?;
                let now_us = super::super::start::now_unix_micros()?;
                let lease = self
                    .external
                    .active_lease(&project, &agent_id, now_us)?
                    .ok_or_else(|| {
                        SeError::invalid(
                            "external mail wait",
                            "an active unexpired external seat for this agent; it was revoked, expired, or disconnected",
                        )
                    })?;
                Ok(ExternalCall::MailWait {
                    principal: WaitPrincipal::OwnerForExternal {
                        project,
                        agent: agent_id,
                        session_id: lease.session_id,
                        credential_id: lease.credential_id,
                        lease_generation: lease.lease_generation,
                    },
                    after,
                    timeout_ms,
                })
            }
            _ => Err(SeError::invalid(
                "mail wait authority",
                "an active external seat capability, managed session capability, or owner terminal with `--as <agent>`",
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn require_external_owner(
        &self,
        phase: &mut se_store::ReadPhase,
        peer: &PeerProof,
        connection: &PresentedAuthority,
        override_authority: Option<&PresentedAuthority>,
        grant: &ConnectionGrant,
        presence: Option<&crate::client::presence::OwnerPresence>,
        op: &str,
    ) -> Result<()> {
        if override_authority.is_some() {
            return Err(SeError::invalid(
                "external owner control",
                "an owner-authenticated native terminal connection without per-call overrides",
            ));
        }
        let (admission, _terminal) = self.caller(phase, peer, connection, None, grant, presence)?;
        if !matches!(admission.actor, Actor::Human(_)) || admission.session.is_some() {
            return Err(SeError::new(se_types::Detail::OwnerRequired(
                se_types::details::OwnerRequired { op: op.into() },
            )));
        }
        crate::client::presence::OwnerPresence::require_owner_cli(presence, peer, op)
    }
}

/// Shared bridge connection binding state, serialized under one mutex so
/// `Approve` handoff and connection-close/timeout cleanup can never race
/// into stranding a committed seat.
#[derive(Default)]
pub(crate) struct BridgeBinding {
    pub closed: bool,
    pub active: Option<(ProjectId, AgentId, SessionId, u64)>,
}

/// Active external lease binding attached to a bridge's connection grant.
pub(crate) type ActiveConnectionBinding = BridgeBinding;

fn check_bound_project(admission: &Admission, requested: Option<&ProjectId>) -> Result<()> {
    if let Some(project) = requested
        && admission.scope != Scope::Project(project.clone())
    {
        return Err(SeError::invalid(
            "project selection",
            "the authenticated session's bound project",
        ));
    }
    Ok(())
}
