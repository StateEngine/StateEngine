use super::{AdmissionContext, Pending, RELAUNCH, SESSION_CAPABILITY, policy_error};
use se_core::store_error::store_error;
use se_store::Snapshot;
use se_store::{Actor, Admission, Scope};
use se_types::{Read, Result, SeError, Sha256};
use sha2::{Digest, Sha256 as Hasher};
use std::io::Read as ByteRead;
use zeroize::Zeroizing;
impl AdmissionContext {
    /// Load the pinned original policy proof and validate its live session together.
    pub(crate) fn saved_session_capability(
        &self,
        profile: &std::path::Path,
        expected: Option<Sha256>,
        session: &crate::SessionIdentity,
    ) -> Result<se_types::Secret> {
        let expected = expected.ok_or_else(|| policy_error("original policy digest is absent"))?;
        let files = se_proc::NativeProfileFiles::open(profile).map_err(policy_error)?;
        let mut file = files
            .readback(&profile.join("host-policy.json"))
            .map_err(policy_error)?
            .ok_or_else(|| policy_error("original policy is absent"))?;
        let mut bytes = Zeroizing::new(Vec::new());
        std::io::Read::by_ref(&mut file)
            .take(1_048_577)
            .read_to_end(&mut bytes)
            .map_err(policy_error)?;
        if bytes.len() > 1_048_576
            || <[u8; 32]>::from(Hasher::digest(bytes.as_slice())) != *expected.as_bytes()
        {
            return Err(policy_error(
                "original policy digest differs or exceeds its bound",
            ));
        }
        let mut policy: serde_json::Value = serde_json::from_slice(&bytes).map_err(policy_error)?;
        let proof = policy
            .pointer_mut("/mcp/stateengine/headers/X-StateEngine-Session-Proof")
            .map(serde_json::Value::take)
            .ok_or_else(|| policy_error("session proof is absent"))?;
        let serde_json::Value::String(proof) = proof else {
            return Err(policy_error("session proof is not a string"));
        };
        let proof = Zeroizing::new(proof);
        let credential = se_types::Secret::new(proof.as_bytes().to_vec())?;
        self.verify_session_capability(&credential, session)?;
        Ok(credential)
    }
}
impl AdmissionContext {
    pub(in crate::runtime) fn session(
        &self,
        phase: &se_store::ReadPhase,
        secret: &se_types::Secret,
    ) -> Result<Admission> {
        self.credential(phase, secret, SESSION_CAPABILITY)
    }
    /// One active credential of exactly `purpose`. The pin capability and the
    /// HTTP bearer are separate secrets (section 70 §2.2): neither is accepted
    /// on the other's transport.
    pub(super) fn credential(
        &self,
        phase: &se_store::ReadPhase,
        secret: &se_types::Secret,
        purpose: &'static str,
    ) -> Result<Admission> {
        self.credential_in(phase, secret, purpose, Pending::Refuse)
    }
    pub(super) fn credential_in(
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
        let now = super::super::start::now_unix_micros()?;
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
                _ if pending != Pending::Discover
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
                    if pending != Pending::ValidateOnly {
                        self.observe_prepared(phase, &credential, hash, purpose)?;
                    }
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
}
impl AdmissionContext {
    /// Re-presenting a protected launch proof uses the normal current-session
    /// verifier, including expiry, revocation and unproved-stop fences.
    pub(crate) fn verify_session_capability(
        &self,
        secret: &se_types::Secret,
        expected: &crate::SessionIdentity,
    ) -> Result<()> {
        let phase = self.reads.read_phase().map_err(|e| store_error(&e))?;
        let admitted = match (|| -> Result<Admission> {
            self.check_generation(&phase)?;
            let admitted = self.session(&phase, secret)?;
            if admitted.scope != Scope::Project(expected.project.clone())
                || admitted.actor != Actor::Agent(expected.agent.clone())
                || admitted.session.as_ref() != Some(&expected.session)
            {
                return Err(SeError::new(se_types::Detail::CapabilityInvalid(
                    se_types::details::CapabilityInvalid {
                        subject: "presented".into(),
                        reason: "credential belongs to another launched session".into(),
                        next_step: "Present the original proof for this agent's current session."
                            .into(),
                    },
                )));
            }
            Ok(admitted)
        })() {
            Ok(admitted) => admitted,
            Err(error) => return super::super::executor::close_read(Err(error), phase.close()),
        };
        let mut read = phase
            .into_snapshot(se_core::admission::read_scope(&admitted))
            .map_err(|error| store_error(&error))?;
        let result = (|| {
            let current = se_core::scope::require_present(
                read.session(expected.session.clone())
                    .map_err(|error| store_error(&error))?,
                "session capability owner",
                "Reconcile the original launched session.",
            )?;
            if !matches!(
                current.current.body,
                se_store::EventBody::SessionActivated { .. }
            ) {
                return Err(SeError::new(se_types::Detail::CapabilityInvalid(
                    se_types::details::CapabilityInvalid {
                        subject: "presented".into(),
                        reason: "launched session is no longer active".into(),
                        next_step: RELAUNCH.into(),
                    },
                )));
            }
            Ok(())
        })();
        super::super::executor::close_read(result, read.close())
    }
}
