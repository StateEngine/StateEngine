use super::{AdmissionContext, ConnectionGrant};
use crate::{HandshakeInput, PeerProof, PendingIpcHandshake, PresentedAuthority};
use se_core::{admission::HumanTerminal, store_error::store_error};
use se_store::{Actor, Admission, Scope};
use se_types::{Result, SeError, Sha256};
use sha2::{Digest, Sha256 as Hasher};
impl AdmissionContext {
    pub fn handshake(&self, pending: &mut PendingIpcHandshake) -> Result<ConnectionGrant> {
        if let HandshakeInput::Call(crate::ClientHello {
            authority: PresentedAuthority::GuestBootstrap(cwd),
            ..
        }) = pending.input()
        {
            return self.guest_handshake(pending.peer(), cwd);
        }
        if let HandshakeInput::Call(crate::ClientHello {
            authority: PresentedAuthority::SessionBootstrap(secret),
            ..
        }) = pending.input()
        {
            return self.session_handshake(pending.peer(), secret);
        }
        let mut phase = self.reads.read_phase().map_err(|e| store_error(&e))?;
        let result = (|| {
            self.check_generation(&phase)?;
            match pending.input() {
                HandshakeInput::Call(hello) => match &hello.authority {
                    PresentedAuthority::OwnerProof { .. } => {
                        self.owner_handshake(&mut phase, pending)
                    }
                    PresentedAuthority::Session(secret) => {
                        self.session(&phase, secret)?;
                        Ok(ConnectionGrant {
                            owner_key: None,
                            guest: None,
                        })
                    }
                    PresentedAuthority::GuestBootstrap(_)
                    | PresentedAuthority::SessionBootstrap(_)
                    | PresentedAuthority::Lease(_) => Err(SeError::invalid(
                        "guest credential",
                        "the native bootstrap connection that issued it",
                    )),
                    PresentedAuthority::Launch(_) => Err(SeError::invalid(
                        "launch credential",
                        "the dedicated prepared launch-activation route",
                    )),
                },
                HandshakeInput::Stop(_) => self.owner_handshake(&mut phase, pending),
                HandshakeInput::Rebind(_) => Err(SeError::invalid(
                    "rebind",
                    "the dedicated native restart route",
                )),
            }
        })();
        super::super::executor::close_read(result, phase.close())
    }
    fn owner_handshake(
        &self,
        phase: &mut se_store::ReadPhase,
        pending: &mut PendingIpcHandshake,
    ) -> Result<ConnectionGrant> {
        self.owner_peer(phase, pending.peer())?;
        let key = self.machine_key()?;
        pending.verify_owner_mac(&key)?;
        Ok(ConnectionGrant {
            owner_key: Some(Sha256::from_bytes(Hasher::digest(key.expose()).into())),
            guest: None,
        })
    }
    /// One native caller check shared by ordinary operations and the closed
    /// remote Owner controls. The latter still require actual human presence.
    pub(super) fn caller(
        &self,
        phase: &mut se_store::ReadPhase,
        peer: &PeerProof,
        connection: &PresentedAuthority,
        override_authority: Option<&PresentedAuthority>,
        grant: &ConnectionGrant,
        presence: Option<&crate::client::presence::OwnerPresence>,
    ) -> Result<(Admission, HumanTerminal)> {
        Ok(match override_authority {
            Some(PresentedAuthority::Lease(secret)) => (
                self.lease_caller(phase, peer, connection, grant, secret)?,
                HumanTerminal::Refused {
                    reason: "a leased connection cannot become an owner terminal".into(),
                },
            ),
            Some(PresentedAuthority::Session(secret)) => (
                self.session(phase, secret)?,
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
                    self.session(phase, secret)?,
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
                    self.owner_peer(phase, peer)?;
                    let peer_owner = match peer.native().principal() {
                        se_proc::native_ipc::IpcPrincipal::Unix { uid } => uid.to_string(),
                        se_proc::native_ipc::IpcPrincipal::Windows { sid } => sid.clone(),
                    };
                    let terminal = match presence {
                        Some(observed) if observed.passes(&peer_owner) => {
                            HumanTerminal::OutsideAgentTree
                        }
                        Some(observed) => HumanTerminal::Refused {
                            reason: observed.refusal_reason(&peer_owner),
                        },
                        None => HumanTerminal::Refused {
                            reason: "the native CLI's human-presence observation is absent".into(),
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
                PresentedAuthority::GuestBootstrap(_)
                | PresentedAuthority::SessionBootstrap(_)
                | PresentedAuthority::Lease(_) => {
                    return Err(SeError::invalid(
                        "guest connection",
                        "its current channel-bound guest ticket",
                    ));
                }
            },
        })
    }
}
