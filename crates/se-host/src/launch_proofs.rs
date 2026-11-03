//! First verified uses of the two exact C1 credentials. The transport
//! authenticator supplies these facts; provider stdout cannot supply them.
use crate::client::lease::Deadline;
use std::sync::Arc;

use se_store::RecordId;
use se_types::{Result, SessionId};
use std::{collections::BTreeMap, sync::Mutex};

/// Trusted authentication result, with no wire deserializer. Construct only
/// after checking the current prepared credential, purpose, expiry and scope.
pub struct VerifiedPreparedRequest {
    pub session: SessionId,
    pub purpose: &'static str,
    pub secret_sha256: [u8; 32],
    pub generation: u64,
    pub request: RecordId,
}
struct Slot {
    generation: u64,
    hashes: [[u8; 32]; 2],
    first: [Option<RecordId>; 2],
}
struct Inner {
    maximum: usize,
    slots: Mutex<BTreeMap<SessionId, Slot>>,
    changed: tokio::sync::Notify,
}
/// Cloneable handoff retained by the existing host authenticator. It carries
/// hashes and request facts, never plaintext secrets or a coordinator cycle.
#[derive(Clone)]
pub struct PreparedRequestProofs(Arc<Inner>);
impl PreparedRequestProofs {
    pub fn new(maximum: u32) -> Self {
        Self(Arc::new(Inner {
            maximum: maximum as usize,
            slots: Mutex::default(),
            changed: tokio::sync::Notify::new(),
        }))
    }
    pub fn register(
        &self,
        session: SessionId,
        generation: u64,
        session_hash: [u8; 32],
        http_hash: [u8; 32],
    ) -> Result<()> {
        let mut slots = self
            .0
            .slots
            .lock()
            .map_err(|_| proof_error("credential readiness", "poisoned verifier registry"))?;
        if slots.contains_key(&session) {
            return Err(proof_error(
                "credential readiness",
                "this session already has a retained verifier slot",
            ));
        }
        if slots.len() >= self.0.maximum {
            return Err(proof_error(
                "credential readiness",
                "resolve retained launch readiness before issuing more credentials",
            ));
        }
        slots.insert(
            session,
            Slot {
                generation,
                hashes: [session_hash, http_hash],
                first: [None, None],
            },
        );
        Ok(())
    }
    /// Authentication calls this after verifying actual possession. It does
    /// not activate a credential or admit an operation before C3.
    pub fn observe_verified(&self, observed: VerifiedPreparedRequest) -> Result<()> {
        let index = match observed.purpose {
            "session" => 0,
            "http" => 1,
            _ => {
                return Err(proof_error(
                    "prepared request purpose",
                    "session or http required",
                ));
            }
        };
        let mut slots = self
            .0
            .slots
            .lock()
            .map_err(|_| proof_error("credential readiness", "poisoned verifier registry"))?;
        let slot = slots.get_mut(&observed.session).ok_or_else(|| {
            proof_error(
                "prepared request",
                "no retained C1 verifier slot for this exact session",
            )
        })?;
        if slot.generation != observed.generation || slot.hashes[index] != observed.secret_sha256 {
            return Err(proof_error(
                "prepared request",
                "verified credential differs from the issued purpose or generation",
            ));
        }
        if slot.first[index].is_none() {
            slot.first[index] = Some(observed.request);
        }
        drop(slots);
        self.0.changed.notify_waiters();
        Ok(())
    }
    pub async fn wait(
        &self,
        session: &SessionId,
        deadline: &Deadline,
    ) -> Result<PreparedFirstRequests> {
        loop {
            deadline.remaining()?;
            let changed = self.0.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let slots = self.0.slots.lock().map_err(|_| {
                    proof_error("credential readiness", "poisoned verifier registry")
                })?;
                let slot = slots.get(session).ok_or_else(|| {
                    proof_error(
                        "credential readiness",
                        "the exact issued session has no retained verifier slot",
                    )
                })?;
                if let [Some(session_request), Some(http_request)] = slot.first {
                    return Ok(PreparedFirstRequests {
                        session_request,
                        http_request,
                    });
                }
            }
            tokio::time::timeout_at(tokio::time::Instant::from_std(deadline.at()),changed).await.map_err(|_|proof_error("credential readiness","actual first-use request witnesses did not arrive before the original launch deadline; no credential was activated"))?;
        }
    }
    pub fn remove(&self, session: &SessionId) -> Result<()> {
        self.0
            .slots
            .lock()
            .map_err(|_| proof_error("credential readiness", "poisoned verifier registry"))?
            .remove(session);
        self.0.changed.notify_waiters();
        Ok(())
    }
}

/// Actual verified request identities returned only after both purposes arrive.
pub struct PreparedFirstRequests {
    pub session_request: RecordId,
    pub http_request: RecordId,
}
fn proof_error(subject: &str, cause: impl std::fmt::Debug) -> se_types::SeError {
    se_core::scope::unreadable(subject, &format!("{cause:?}"))
}
