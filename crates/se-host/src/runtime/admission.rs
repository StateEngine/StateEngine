//! Authenticate native observations and current protected credentials before an
//! admitted snapshot exists. An override is checked on its own, never retried
//! using the connection's earlier authority.
use super::*;
use crate::{PeerProof, PresentedAuthority, RawOperation};
use se_core::{
    ops::{self, CliSelections},
    store_error::store_error,
};
use se_store::{Actor, Scope};
use se_types::{Read, Result, SeError, Sha256};
use sha2::{Digest, Sha256 as Hasher};
use std::sync::{Arc, Weak};
mod adoption;
mod channel;
mod codex;
mod credential;
mod handshake;
mod http;
mod operation;
mod owner;
#[cfg(feature = "remote")]
mod remote;

/// Whether a still-prepared credential may be used: only for read-only tool
/// discovery during its launch, never for an operation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(in crate::runtime::admission) enum Pending {
    Discover,
    Refuse,
    ValidateOnly,
}
const RELAUNCH: &str = "relaunch the agent with `se launch AGENT`";
/// Purpose of the pin capability (`sec1.`) CLI, hooks and IPC present.
pub(crate) const SESSION_CAPABILITY: &str = "session";
#[derive(Clone)]
pub(crate) struct AdmissionContext {
    pub reads: se_store::ReadPhasePool,
    // Retained routers borrow admission authority; only the runtime and its
    // writer obligations own the lease after the admission fence is joined.
    pub lease: Weak<HostLease>,
    pub owner: se_types::HumanId,
    pub generation: se_types::Generation,
    pub image_sha256: se_types::Sha256,
    pub state_directory: std::path::PathBuf,
    pub configuration: Option<se_config::config_policy::ConfigFile>,
    /// Exact selected configuration file; absent when the embedded caller
    /// configured values without a file. The origin label is derived here so
    /// the host never invents an origin for in-memory configuration.
    pub configuration_file: Option<std::path::PathBuf>,
    pub prepared_requests: Arc<std::sync::OnceLock<crate::PreparedRequestProofs>>,
}
/// A successful owner MAC is channel-bound. Its digest lets each subsequent
/// call detect machine-key replacement without retaining another secret copy.
pub(crate) struct ConnectionGrant {
    pub owner_key: Option<Sha256>,
    pub(crate) guest: Option<crate::mcp_lease::LeaseGrant>,
}
impl ConnectionGrant {
    pub(crate) fn connection_ticket(&self) -> Option<crate::ConnectionTicket> {
        self.guest.as_ref().map(|guest| guest.ticket.clone())
    }
}
pub(crate) struct OperationMetadata {
    pub selections: Option<serde_json::Value>,
    pub presence: Option<crate::client::presence::OwnerPresence>,
}
impl AdmissionContext {
    pub(crate) fn lease(&self) -> Result<Arc<HostLease>> {
        self.lease.upgrade().ok_or_else(|| {
            SeError::new(se_types::Detail::RuntimeNotRunning(
                se_types::details::RuntimeNotRunning {
                    op: "host admission".into(),
                    reason: "this retained handle's original host lease has been released".into(),
                },
            ))
        })
    }
    #[cfg(test)]
    pub fn operation(
        &self,
        peer: &PeerProof,
        connection: &PresentedAuthority,
        override_authority: Option<&PresentedAuthority>,
        grant: &ConnectionGrant,
        raw: RawOperation,
        metadata: OperationMetadata,
    ) -> Result<HostedCall> {
        self.with_operation(
            (peer, connection),
            override_authority,
            grant,
            raw,
            metadata,
            |phase, call| super::executor::close_read(Ok(call), phase.close()),
        )
    }
    pub fn with_operation<T>(
        &self,
        native: (&PeerProof, &PresentedAuthority),
        override_authority: Option<&PresentedAuthority>,
        grant: &ConnectionGrant,
        raw: RawOperation,
        metadata: OperationMetadata,
        finish: impl FnOnce(se_store::ReadPhase, HostedCall) -> Result<T>,
    ) -> Result<T> {
        let (peer, connection) = native;
        let mut phase = self.reads.read_phase().map_err(|e| store_error(&e))?;
        let result = (|| {
            self.check_generation(&phase)?;
            let operation = ops::decode_operation(&raw.name, raw.arguments, raw.key.as_ref())?;
            let selections: Option<CliSelections> = metadata
                .selections
                .map(serde_json::from_value)
                .transpose()
                .map_err(|_| {
                    SeError::invalid("CLI selections", "the core's closed CliSelections object")
                })?;
            if let Some(selection) = &selections {
                selection.validate()?;
            }
            let (mut admission, terminal) = self.caller(
                &mut phase,
                peer,
                connection,
                override_authority,
                grant,
                metadata.presence.as_ref(),
            )?;
            if let Some(project) = selections.as_ref().and_then(|value| value.project.as_ref()) {
                match (&admission.actor, &admission.scope) {
                    (Actor::Agent(_), Scope::Project(bound)) if bound != project => {
                        return Err(SeError::invalid(
                            "CLI project selection",
                            "the authenticated session's exact project",
                        ));
                    }
                    (Actor::Human(_), _) => admission.scope = Scope::Project(project.clone()),
                    _ => (),
                }
            }
            // Principal/scope admission precedes execution; Kernel::plan applies
            // presence policy to this verified terminal fact before any effects.
            se_core::admission::authorize(operation.meta(), &admission)?;
            let mut facts = allocate_facts()?;
            facts.door = if matches!(&operation, ops::AnyOp::HookClaude(_)) {
                se_store::Door::Hook
            } else if selections.is_some() {
                se_store::Door::Cli
            } else {
                se_store::Door::Mcp
            };
            let remote_credential = if operation.is_remote() {
                match override_authority.unwrap_or(connection) {
                    PresentedAuthority::Session(secret) => Some(remote_credential(&phase, secret)?),
                    _ => None,
                }
            } else {
                None
            };
            Ok(HostedCall {
                remote_credential,
                input: HostedInput::Operation(operation),
                kernel: self.kernel(facts)?,
                admission,
                terminal,
                selections,
            })
        })();
        match result {
            Ok(call) => finish(phase, call),
            Err(error) => super::executor::close_read(Err(error), phase.close()),
        }
    }
    pub(crate) fn check_generation(&self, phase: &se_store::ReadPhase) -> Result<()> {
        match phase.runtime_owner().map_err(|e| store_error(&e))? {
            Read::Present { value } if value.generation == self.generation => Ok(()),
            _ => Err(SeError::invalid(
                "host generation",
                "the same present committed runtime owner generation",
            )),
        }
    }
}
impl HostedRuntime {
    pub(crate) fn admission_context(&self) -> AdmissionContext {
        AdmissionContext {
            configuration: self.configuration.clone(),
            configuration_file: self.configuration_file.clone(),
            prepared_requests: self.prepared_requests.clone(),
            reads: self.admission_reads.clone(),
            lease: Arc::downgrade(&self.lease),
            owner: self.owner.clone(),
            generation: self.generation(),
            image_sha256: self.image_sha256,
            state_directory: self.state_directory.clone(),
        }
    }
}

pub(in crate::runtime::admission) fn remote_credential(
    phase: &se_store::ReadPhase,
    secret: &se_types::Secret,
) -> Result<(se_store::RecordId, [u8; 32])> {
    let hash: [u8; 32] = Hasher::digest(secret.expose()).into();
    match phase.credential(hash).map_err(|e| store_error(&e))? {
        Read::Present { value } if value.state == se_store::CredentialState::Active => {
            Ok((value.credential, hash))
        }
        _ => Err(SeError::invalid(
            "remote source credential",
            "the exact already-admitted active credential",
        )),
    }
}

fn policy_error(cause: impl std::fmt::Display) -> SeError {
    se_core::scope::unreadable("SE Code capability policy", &cause.to_string())
}
