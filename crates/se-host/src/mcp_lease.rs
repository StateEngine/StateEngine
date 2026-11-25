//! Identity-free native connections are scoped to one registered project.
use crate::{
    PeerProof, PresentedAuthority,
    runtime::admission::{AdmissionContext, ConnectionGrant, SESSION_CAPABILITY},
};
use se_core::store_error::store_error;
use se_store::{Actor, Admission, Scope, Snapshot};
use se_types::{Result, SeError};
use sha2::{Digest, Sha256 as Hasher};
use std::sync::Arc;
mod custody;
use std::time::{Duration, Instant};

pub(crate) struct LeaseGrant {
    pub(crate) ticket: crate::ConnectionTicket,
    expires: Instant,
    peer: Vec<u8>,
    original: Option<[u8; 32]>,
}

impl AdmissionContext {
    pub(crate) fn session_handshake(
        &self,
        peer: &PeerProof,
        secret: &se_types::Secret,
    ) -> Result<ConnectionGrant> {
        let credential = self.renewal_identity(peer, secret)?;
        let lifetime_ms = 60_000;
        let ticket = crate::ConnectionTicket {
            project: credential.project,
            agent: Some(credential.agent),
            session: Some(credential.session),
            secret: Arc::new(se_types::Secret::new(
                crate::client::auth::fresh_nonce()?.to_vec(),
            )?),
            lifetime_ms,
        };
        let expires = Instant::now()
            .checked_add(Duration::from_millis(lifetime_ms))
            .ok_or_else(|| SeError::invalid("session ticket", "a finite lifetime"))?;
        Ok(ConnectionGrant {
            owner_key: None,
            guest: Some(LeaseGrant {
                ticket,
                expires,
                peer: peer.native().binding(),
                original: Some(Hasher::digest(secret.expose()).into()),
            }),
        })
    }

    pub(crate) fn guest_handshake(
        &self,
        peer: &PeerProof,
        cwd: &se_types::NativePath,
    ) -> Result<ConnectionGrant> {
        let phase = self
            .reads
            .read_phase()
            .map_err(|error| store_error(&error))?;
        let checked = self.check_generation(&phase);
        crate::runtime::executor::close_read(checked, phase.close())?;
        let local = se_proc::native_ipc::observe_ipc_self().map_err(|error| {
            se_core::scope::unreadable("native host identity", &error.to_string())
        })?;
        if peer.native().principal() != local.principal() {
            return Err(SeError::invalid(
                "guest connection",
                "the same native account as the host",
            ));
        }
        if peer.native().image_sha256() != self.image_sha256 {
            return Err(SeError::invalid(
                "guest connection",
                "the installed StateEngine executable",
            ));
        }
        let cwd = std::fs::canonicalize(cwd.to_local()?)
            .map_err(|error| se_core::scope::unreadable("current directory", &error.to_string()))?;
        if !cwd.is_dir() {
            return Err(SeError::invalid(
                "current directory",
                "a directory inside a registered project; run se init in the repository",
            ));
        }
        let project = self.guest_project(&cwd)?;
        let lifetime_ms = 60_000;
        let ticket = crate::ConnectionTicket {
            project,
            agent: None,
            session: None,
            secret: Arc::new(se_types::Secret::new(
                crate::client::auth::fresh_nonce()?.to_vec(),
            )?),
            lifetime_ms,
        };
        let expires = Instant::now()
            .checked_add(Duration::from_millis(lifetime_ms))
            .ok_or_else(|| SeError::invalid("guest credential", "a finite lifetime"))?;
        Ok(ConnectionGrant {
            owner_key: None,
            guest: Some(LeaseGrant {
                ticket,
                expires,
                peer: peer.native().binding(),
                original: None,
            }),
        })
    }

    fn guest_project(&self, cwd: &std::path::Path) -> Result<se_types::ProjectId> {
        let phase = self
            .reads
            .read_phase()
            .map_err(|error| store_error(&error))?;
        if let Err(error) = self.check_generation(&phase) {
            return crate::runtime::executor::close_read(Err(error), phase.close());
        }
        let admission = Admission {
            scope: Scope::Registry,
            actor: Actor::Human(self.owner.clone()),
            session: None,
            generation: self.generation.get(),
        };
        let mut snapshot = phase
            .into_snapshot(se_core::admission::read_scope(&admission))
            .map_err(|error| store_error(&error))?;
        let result = (|| {
            let mut after = None;
            let mut candidates = Vec::new();
            for _ in 0..64 {
                let page = snapshot
                    .projects(crate::read_budget(
                        after,
                        100,
                        1024 * 1024,
                        Duration::from_secs(1),
                    ))
                    .map_err(|error| store_error(&error))?;
                let next = page.next().cloned();
                let complete = page.window().complete();
                for record in page.into_items() {
                    let (project, roots) = match record.current.body {
                        se_store::EventBody::ProjectRegistered { project, roots, .. }
                        | se_store::EventBody::ProjectUpdated { project, roots, .. } => {
                            (project, roots)
                        }
                        se_store::EventBody::ProjectMoved { project, to, .. } => {
                            (project, vec![to])
                        }
                        _ => {
                            return Err(se_core::scope::unreadable(
                                "project selection",
                                "unexpected project metadata",
                            ));
                        }
                    };
                    for root in roots {
                        let root = match std::fs::canonicalize(root.path.to_local()?) {
                            Ok(root) => root,
                            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                            Err(error) => {
                                return Err(se_core::scope::unreadable(
                                    "registered project root",
                                    &error.to_string(),
                                ));
                            }
                        };
                        if cwd.starts_with(&root) {
                            candidates.push((root.components().count(), project.clone()));
                        }
                    }
                }
                match next {
                    Some(cursor) => after = Some(cursor),
                    None if complete => {
                        let nearest = candidates.iter().map(|(depth, _)| *depth).max();
                        candidates.retain(|(depth, _)| Some(*depth) == nearest);
                        candidates.sort();
                        candidates.dedup();
                        return match candidates.as_slice() {
                            [(_, project)] => Ok(project.clone()),
                            [] => Err(SeError::invalid(
                                "current directory",
                                "a registered project; run se init in the repository",
                            )),
                            _ => Err(se_core::scope::unreadable(
                                "project selection",
                                "multiple registered projects match this directory",
                            )),
                        };
                    }
                    None => break,
                }
            }
            Err(se_core::scope::unreadable(
                "project selection",
                "registered project inventory is incomplete",
            ))
        })();
        let closed = snapshot.close();
        crate::runtime::executor::close_read(result, closed)
    }

    pub(crate) fn lease_caller(
        &self,
        phase: &se_store::ReadPhase,
        peer: &PeerProof,
        connection: &PresentedAuthority,
        grant: &ConnectionGrant,
        secret: &se_types::Secret,
    ) -> Result<Admission> {
        let guest = grant
            .guest
            .as_ref()
            .ok_or_else(|| SeError::invalid("guest credential", "the issuing native connection"))?;
        let expected = guest.ticket.secret.expose();
        let supplied = secret.expose();
        if !matches!(
            connection,
            PresentedAuthority::GuestBootstrap(_) | PresentedAuthority::SessionBootstrap(_)
        ) || Instant::now() >= guest.expires
            || peer.native().binding() != guest.peer
            || supplied.len() != expected.len()
            || supplied
                .iter()
                .zip(expected)
                .fold(0u8, |difference, (a, b)| difference | (a ^ b))
                != 0
        {
            return Err(SeError::invalid(
                "guest credential",
                "the current unexpired ticket for this native connection",
            ));
        }
        let (actor, session) = match (&guest.original, &guest.ticket.agent, &guest.ticket.session) {
            (None, None, None) if matches!(connection, PresentedAuthority::GuestBootstrap(_)) => {
                (Actor::Guest, None)
            }
            (Some(hash), Some(agent), Some(session))
                if matches!(connection, PresentedAuthority::SessionBootstrap(_)) =>
            {
                let record = se_core::scope::require_present(
                    phase
                        .credential(*hash)
                        .map_err(|error| store_error(&error))?,
                    "renewed session",
                    "Launch through se launch with the original session.",
                )?;
                if record.project != guest.ticket.project
                    || record.agent != *agent
                    || record.session != *session
                    || record.purpose != SESSION_CAPABILITY
                    || record.state != se_store::CredentialState::Active
                    || phase
                        .credential_stop_unproved(*hash)
                        .map_err(|error| store_error(&error))?
                    || phase
                        .credential_superseded(*hash)
                        .map_err(|error| store_error(&error))?
                    || !record.session_active
                {
                    return Err(SeError::invalid(
                        "renewed session",
                        "the same unfenced active original session",
                    ));
                }
                (Actor::Agent(agent.clone()), Some(session.clone()))
            }
            _ => {
                return Err(SeError::invalid(
                    "session ticket",
                    "the original channel-bound principal",
                ));
            }
        };
        Ok(Admission {
            scope: Scope::Project(guest.ticket.project.clone()),
            actor,
            session,
            generation: self.generation.get(),
        })
    }
}
