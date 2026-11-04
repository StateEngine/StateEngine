//! Authenticate native observations and current protected credentials before an
//! admitted snapshot exists. An override is checked on its own, never retried
//! using the connection's earlier authority.
use super::{
    start::{allocate_facts, owner_budget},
    *,
};
use crate::{HandshakeInput, PeerProof, PendingIpcHandshake, PresentedAuthority, RawOperation};
use se_core::{
    admission::HumanTerminal,
    ops::{self, CliSelections},
    store_error::store_error,
};
use se_store::{Actor, Admission, RuntimeLease, Scope};
use se_types::{Read, Result, SeError, Sha256};
use sha2::{Digest, Sha256 as Hasher};
use std::{
    io::Read as ByteRead,
    sync::{Arc, Weak},
};
use zeroize::Zeroizing;
mod http;

/// Whether a still-prepared credential may be used: only for read-only tool
/// discovery during its launch, never for an operation.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Pending {
    Discover,
    Refuse,
}
const RELAUNCH: &str = "relaunch the agent with `se launch AGENT`";
/// Purpose of the pin capability (`sec1.`) CLI, hooks and IPC present.
const SESSION_CAPABILITY: &str = "session";
#[derive(Clone)]
pub(crate) struct AdmissionContext {
    pub reads: se_store::ReadPhasePool,
    // Retained routers borrow admission authority; only the runtime and its
    // writer obligations own the lease after the admission fence is joined.
    pub lease: Weak<HostLease>,
    pub owner: se_types::HumanId,
    pub generation: se_types::Generation,
    pub state_directory: std::path::PathBuf,
    pub configuration: Option<se_core::config_policy::ConfigFile>,
    pub prepared_requests: Arc<std::sync::OnceLock<crate::PreparedRequestProofs>>,
}
/// A successful owner MAC is channel-bound. Its digest lets each subsequent
/// call detect machine-key replacement without retaining another secret copy.
pub(crate) struct ConnectionGrant {
    pub owner_key: Option<Sha256>,
}
pub(crate) struct OperationMetadata {
    pub selections: Option<serde_json::Value>,
    pub presence: Option<crate::client::presence::OwnerPresence>,
}
impl AdmissionContext {
    fn lease(&self) -> Result<Arc<HostLease>> {
        self.lease.upgrade().ok_or_else(|| {
            SeError::new(se_types::Detail::RuntimeNotRunning(
                se_types::details::RuntimeNotRunning {
                    op: "host admission".into(),
                    reason: "this retained handle's original host lease has been released".into(),
                },
            ))
        })
    }
    pub fn handshake(&self, pending: &mut PendingIpcHandshake) -> Result<ConnectionGrant> {
        let phase = self.reads.read_phase().map_err(|e| store_error(&e))?;
        let result = (|| {
            self.check_generation(&phase)?;
            match pending.input() {
                HandshakeInput::Call(hello) => match &hello.authority {
                    PresentedAuthority::OwnerProof { .. } => self.owner_handshake(&phase, pending),
                    PresentedAuthority::Session(secret) => {
                        self.session(&phase, secret)?;
                        Ok(ConnectionGrant { owner_key: None })
                    }
                    PresentedAuthority::Launch(_) => Err(SeError::invalid(
                        "launch credential",
                        "the dedicated prepared launch-activation route",
                    )),
                },
                HandshakeInput::Stop(_) => self.owner_handshake(&phase, pending),
            }
        })();
        super::executor::close_read(result, phase.close())
    }
    fn owner_handshake(
        &self,
        phase: &se_store::ReadPhase,
        pending: &mut PendingIpcHandshake,
    ) -> Result<ConnectionGrant> {
        self.owner_peer(phase, pending.peer())?;
        let key = self.machine_key()?;
        pending.verify_owner_mac(&key)?;
        Ok(ConnectionGrant {
            owner_key: Some(Sha256::from_bytes(Hasher::digest(key.expose()).into())),
        })
    }
    pub fn operation(
        &self,
        peer: &PeerProof,
        connection: &PresentedAuthority,
        override_authority: Option<&PresentedAuthority>,
        grant: &ConnectionGrant,
        raw: RawOperation,
        metadata: OperationMetadata,
    ) -> Result<HostedCall> {
        let phase = self.reads.read_phase().map_err(|e| store_error(&e))?;
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
            let (mut admission, terminal) = match override_authority {
                Some(PresentedAuthority::Session(secret)) => (
                    self.session(&phase, secret)?,
                    HumanTerminal::Refused {
                        reason: "session authority cannot become an owner terminal".into(),
                    },
                ),
                Some(_) => {
                    return Err(SeError::invalid(
                        "per-call authority",
                        "a valid session override; OwnerProof is one-use handshake-only and Launch uses activation",
                    ));
                }
                None => match connection {
                    PresentedAuthority::Session(secret) => (
                        self.session(&phase, secret)?,
                        HumanTerminal::Refused {
                            reason: "session authority cannot become an owner terminal".into(),
                        },
                    ),
                    PresentedAuthority::OwnerProof { .. } => {
                        let key = self.machine_key()?;
                        let current = Sha256::from_bytes(Hasher::digest(key.expose()).into());
                        if grant.owner_key != Some(current) {
                            return Err(SeError::invalid(
                                "owner connection",
                                "the same current protected machine credential",
                            ));
                        }
                        // This rechecks current owner/ancestry against a complete
                        // protected inventory for every request, not just connect.
                        self.owner_peer(&phase, peer)?;
                        let peer_owner = match peer.native().principal() {
                            se_proc::native_ipc::IpcPrincipal::Unix { uid } => uid.to_string(),
                            se_proc::native_ipc::IpcPrincipal::Windows { sid } => sid.clone(),
                        };
                        let terminal = match metadata.presence.as_ref() {
                        Some(observed) if observed.passes(&peer_owner) => HumanTerminal::OutsideAgentTree,
                        _ => HumanTerminal::Refused {
                            reason: "human presence requires the native CLI's stdin/stdout consoles, no session/provider markers, and matching independent peer owner/ancestry checks".into(),
                        },
                    };
                        (
                            Admission {
                                scope: Scope::Registry,
                                actor: Actor::Human(self.owner.clone()),
                                session: None,
                                generation: self.generation.get(),
                            },
                            terminal,
                        )
                    }
                    PresentedAuthority::Launch(_) => {
                        return Err(SeError::invalid(
                            "launch authority",
                            "the dedicated activation route",
                        ));
                    }
                },
            };
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
            Ok(HostedCall {
                input: HostedInput::Operation(operation),
                kernel: self.kernel(facts)?,
                admission,
                terminal,
                selections,
            })
        })();
        super::executor::close_read(result, phase.close())
    }
    /// MCP over loopback HTTP: a current session bearer only. This transport has
    /// no owner proof, launch activation or per-call authority override (§7.3).
    /// The shared consumer has already decoded the tool through core's registry.
    pub fn mcp_call(&self, secret: &se_types::Secret, operation: ops::AnyOp) -> Result<HostedCall> {
        let phase = self.reads.read_phase().map_err(|e| store_error(&e))?;
        let result = (|| {
            self.check_generation(&phase)?;
            let admission = self.credential(&phase, secret, crate::MCP_BEARER_PURPOSE)?;
            se_core::admission::authorize(operation.meta(), &admission)?;
            let mut facts = allocate_facts()?;
            facts.door = se_store::Door::Mcp;
            Ok(HostedCall {
                input: HostedInput::Operation(operation),
                kernel: self.kernel(facts)?,
                admission,
                terminal: HumanTerminal::Refused {
                    reason: "session authority cannot become an owner terminal".into(),
                },
                selections: None,
            })
        })();
        super::executor::close_read(result, phase.close())
    }
    /// Read-only MCP methods still require the same current session bearer.
    pub fn check_session(&self, secret: &se_types::Secret) -> Result<()> {
        let phase = self.reads.read_phase().map_err(|e| store_error(&e))?;
        let result = (|| {
            self.check_generation(&phase)?;
            self.credential_in(&phase, secret, crate::MCP_BEARER_PURPOSE, Pending::Discover)
                .map(drop)
        })();
        super::executor::close_read(result, phase.close())
    }
    fn kernel(&self, facts: se_core::dispatch::CallFacts) -> Result<se_core::dispatch::Kernel> {
        match &self.configuration {
            Some(configuration) => {
                se_core::dispatch::Kernel::new(facts)?.with_configuration(configuration.clone())
            }
            None => se_core::dispatch::Kernel::new(facts),
        }
    }
    fn session(&self, phase: &se_store::ReadPhase, secret: &se_types::Secret) -> Result<Admission> {
        self.credential(phase, secret, SESSION_CAPABILITY)
    }
    /// One active credential of exactly `purpose`. The pin capability and the
    /// HTTP bearer are separate secrets (section 70 §2.2): neither is accepted
    /// on the other's transport.
    fn credential(
        &self,
        phase: &se_store::ReadPhase,
        secret: &se_types::Secret,
        purpose: &'static str,
    ) -> Result<Admission> {
        self.credential_in(phase, secret, purpose, Pending::Refuse)
    }
    fn credential_in(
        &self,
        phase: &se_store::ReadPhase,
        secret: &se_types::Secret,
        purpose: &'static str,
        pending: Pending,
    ) -> Result<Admission> {
        let hash: [u8; 32] = Hasher::digest(secret.expose()).into();
        let credential = match phase.credential(hash).map_err(|e| store_error(&e))? {
            Read::Present { value } => value,
            Read::Absent { .. } => {
                return Err(SeError::invalid(
                    "session credential",
                    "a present active session credential; no owner fallback",
                ));
            }
            Read::Unreadable { reason, .. } => {
                return Err(se_core::scope::unreadable("session credential", &reason));
            }
            Read::Unknown { what } => {
                return Err(se_core::scope::unreadable("session credential", &what));
            }
        };
        let now = super::start::now_unix_micros()?;
        // A launched provider lists its tools before its launch activates. Only
        // that discovery may use a still-prepared credential, and only while it
        // is the agent's current launch before its activation deadline. Each
        // refusal names its own reason and next step; none echoes the secret.
        let refusal =
            if credential.purpose != purpose {
                Some((
                    format!("issued for another purpose, not `{purpose}`"),
                    "present the credential this transport was issued",
                ))
            } else if credential.expires_at_us <= now {
                Some(("expired".to_owned(), RELAUNCH))
            } else {
                match credential.state {
                // Reconciliation could not prove this launch stopped: its agent
                // stays fenced until the owner releases it, active or not.
                _ if pending == Pending::Refuse
                    && phase.credential_stop_unproved(hash).map_err(|e| store_error(&e))? =>
                {
                    Some((
                        "fenced: StateEngine could not prove this agent's earlier process stopped"
                            .to_owned(),
                        "the project owner checks the agent, then stops or releases it",
                    ))
                }
                se_store::CredentialState::Active => None,
                se_store::CredentialState::Revoked => Some((
                    "revoked: this launch was stopped or superseded".to_owned(),
                    RELAUNCH,
                )),
                // An expired or superseded preparation is invalid; only a live,
                // current one that has not finished starting is retryable.
                se_store::CredentialState::Prepared if now >= credential.activation_deadline_us => {
                    Some(("past its launch activation deadline".to_owned(), RELAUNCH))
                }
                se_store::CredentialState::Prepared
                    if phase.credential_superseded(hash).map_err(|e| store_error(&e))? =>
                {
                    Some(("superseded by a later launch of this agent".to_owned(), RELAUNCH))
                }
                se_store::CredentialState::Prepared => {
                    self.observe_prepared(phase, &credential, hash, purpose)?;
                    if pending == Pending::Refuse {
                        return Err(SeError::new(se_types::Detail::SessionNotActive(
                            se_types::details::SessionNotActive {
                                subject: credential.session.as_str().to_owned(),
                            },
                        )));
                    }
                    None
                }
            }
            };
        if let Some((reason, next_step)) = refusal {
            return Err(SeError::new(se_types::Detail::CapabilityInvalid(
                se_types::details::CapabilityInvalid {
                    subject: "presented".into(),
                    reason,
                    next_step: next_step.into(),
                },
            )));
        }
        Ok(Admission {
            scope: Scope::Project(credential.project),
            actor: Actor::Agent(credential.agent),
            session: Some(credential.session),
            generation: self.generation.get(),
        })
    }
    fn machine_key(&self) -> Result<se_types::Secret> {
        let path = self.state_directory.join("credential");
        let lease = self.lease()?;
        let mut file = match lease.files().readback(&path).map_err(|e| store_error(&e))? {
            Read::Present { value } => value,
            _ => {
                return Err(SeError::invalid(
                    "machine credential",
                    "a present protected 32-byte credential from explicit init",
                ));
            }
        };
        let mut bytes = Zeroizing::new(Vec::with_capacity(33));
        (&mut file)
            .take(33)
            .read_to_end(&mut bytes)
            .map_err(|e| se_core::scope::unreadable("machine credential", &e.to_string()))?;
        if bytes.len() != 32 {
            return Err(SeError::invalid(
                "machine credential",
                "exactly 32 protected bytes",
            ));
        }
        se_types::Secret::new(std::mem::take(&mut *bytes))
    }
    fn owner_peer(&self, phase: &se_store::ReadPhase, peer: &PeerProof) -> Result<()> {
        // This finite auth phase deliberately retains its SQL pin through the
        // protected readback and bounded native ancestry observation below.
        // machine_key likewise reads a protected file before the phase closes;
        // none of these synchronous reads submits a write or awaits the network.
        let lease = self.lease()?;
        let inventory = phase
            .owner_guard(lease.files(), owner_budget()?)
            .map_err(|e| store_error(&e))?;
        if inventory.owners.as_slice() != [self.owner.clone()] {
            return Err(SeError::invalid(
                "host owner",
                "the same current protected store owner",
            ));
        }
        let records = super::decode_owner_inventory(&inventory)?;
        let native = peer.native();
        let start = match native.started() {
            se_types::StartIdentity::Linux { start_ticks } => se_proc::StartIdentity::Linux {
                start_ticks: *start_ticks,
            },
            se_types::StartIdentity::Macos {
                start_seconds,
                start_micros,
            } => se_proc::StartIdentity::MacOs {
                seconds: *start_seconds,
                microseconds: *start_micros,
            },
            se_types::StartIdentity::Windows { creation_filetime } => {
                se_proc::StartIdentity::Windows {
                    creation_filetime: creation_filetime.get(),
                }
            }
        };
        let observed = se_proc::observe_owner(
            se_proc::OwnerTarget::Process {
                pid: se_proc::ProcessId(native.pid()),
                start: &start,
            },
            &records,
        )
        .map_err(|e| se_core::scope::unreadable("native IPC peer ancestry", &e.to_string()))?;
        let owner = match observed.owner() {
            se_proc::NativeOwner::Unix {
                real_uid,
                effective_uid,
            } if real_uid == effective_uid => effective_uid.to_string(),
            se_proc::NativeOwner::Windows { sid } => sid.clone(),
            _ => {
                return Err(SeError::invalid(
                    "native peer owner",
                    "matching real and effective OS users",
                ));
            }
        };
        let expected = match native.principal() {
            se_proc::native_ipc::IpcPrincipal::Unix { uid } => uid.to_string(),
            se_proc::native_ipc::IpcPrincipal::Windows { sid } => sid.clone(),
        };
        if owner != expected {
            return Err(SeError::new(se_types::Detail::OsUserMismatch(
                se_types::details::OsUserMismatch {
                    expected,
                    actual: owner,
                },
            )));
        }
        if !observed.agent_trees().is_empty() {
            return Err(SeError::new(se_types::Detail::OwnerRequired(
                se_types::details::OwnerRequired {
                    op: "IPC owner".into(),
                },
            )));
        }
        // Only peer OS identity and native ancestry were observed here. Local
        // CLI provenance checks ambient markers; host flags are never peer facts.
        Ok(())
    }

    fn check_generation(&self, phase: &se_store::ReadPhase) -> Result<()> {
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
            prepared_requests: self.prepared_requests.clone(),
            reads: self.admission_reads.clone(),
            lease: Arc::downgrade(&self.lease),
            owner: self.owner.clone(),
            generation: self.generation(),
            state_directory: self.state_directory.clone(),
        }
    }
}
