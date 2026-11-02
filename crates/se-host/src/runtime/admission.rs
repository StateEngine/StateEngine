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
use std::{io::Read as ByteRead, sync::Arc};
use zeroize::Zeroizing;

#[derive(Clone)]
pub(crate) struct AdmissionContext {
    pub reader: Arc<se_store::SqliteReader>,
    pub lease: Arc<HostLease>,
    pub owner: se_types::HumanId,
    pub generation: se_types::Generation,
    pub state_directory: std::path::PathBuf,
    pub configuration: Option<se_core::config_policy::ConfigFile>,
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
    pub fn handshake(&self, pending: &mut PendingIpcHandshake) -> Result<ConnectionGrant> {
        let phase = self.reader.read_phase().map_err(|e| store_error(&e))?;
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
        let phase = self.reader.read_phase().map_err(|e| store_error(&e))?;
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
                kernel: match &self.configuration {
                    Some(configuration) => se_core::dispatch::Kernel::new(facts)?
                        .with_configuration(configuration.clone())?,
                    None => se_core::dispatch::Kernel::new(facts)?,
                },
                admission,
                terminal,
                selections,
            })
        })();
        super::executor::close_read(result, phase.close())
    }
    fn session(&self, phase: &se_store::ReadPhase, secret: &se_types::Secret) -> Result<Admission> {
        let credential = match phase
            .credential(Hasher::digest(secret.expose()).into())
            .map_err(|e| store_error(&e))?
        {
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
        if credential.state != se_store::CredentialState::Active
            || credential.purpose != "session"
            || credential.expires_at_us <= now
        {
            return Err(SeError::invalid(
                "session credential",
                "an unrevoked active session-purpose credential before its expiry",
            ));
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
        let mut file = match self
            .lease
            .files()
            .readback(&path)
            .map_err(|e| store_error(&e))?
        {
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
        let inventory = phase
            .owner_guard(self.lease.files(), owner_budget()?)
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
            reader: Arc::clone(&self.execution.reader),
            lease: Arc::clone(&self.lease),
            owner: self.owner.clone(),
            generation: self.generation(),
            state_directory: self.state_directory.clone(),
        }
    }
}
