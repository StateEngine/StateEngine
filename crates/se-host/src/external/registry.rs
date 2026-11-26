//! In-memory pending claim and active external lease registry for one host generation.
//! Claims are bound to exact native peer/birth, connection nonce, host generation,
//! expiry, and (project_id, agent_id, scope), and are consumed at most once.
use super::*;
use se_types::{AgentId, Generation, ProjectId, Result, SeError, Secret, SessionId};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::oneshot;

const MAX_PENDING_CLAIMS: usize = 64;

/// Delivered to the exact waiting bridge connection once approved by the Owner.
pub(crate) struct ClaimApprovalDelivery {
    pub project_id: ProjectId,
    pub agent_id: AgentId,
    pub agent_name: String,
    pub session_id: SessionId,
    pub lease_generation: u64,
    pub expires_at_us: i64,
    pub secret: Arc<Secret>,
}

/// Handle retained on the bridge's `ConnectionGrant` for its lifetime.
#[derive(Clone, Debug)]
pub(crate) struct PendingClaimHandle {
    pub claim_id: String,
    pub project_id: ProjectId,
    pub agent_id: AgentId,
    pub agent_name: String,
    pub peer_binding: Vec<u8>,
    pub connection_nonce: [u8; 32],
    pub host_generation: Generation,
    pub expires_at_us: i64,
}

struct PendingClaimEntry {
    claim_id: String,
    project_id: ProjectId,
    agent_id: AgentId,
    agent_name: String,
    scope: String,
    peer_pid: u32,
    host_generation: Generation,
    expires_at: Instant,
    expires_at_us: i64,
    delivery: oneshot::Sender<ClaimApprovalDelivery>,
    bridge: Arc<Mutex<crate::runtime::admission::external::BridgeBinding>>,
}

struct ClaimReceiver {
    peer_binding: Vec<u8>,
    connection_nonce: [u8; 32],
    host_generation: Generation,
    expires_at: Instant,
    approved: bool,
    rx: oneshot::Receiver<ClaimApprovalDelivery>,
}

/// Read-only view of a pending claim before it is consumed.
pub(crate) struct PeekedClaim {
    pub project_id: ProjectId,
    pub agent_id: AgentId,
}

/// One consumed claim ready for atomic store commit and secret delivery.
pub(crate) struct ConsumedClaim {
    pub claim_id: String,
    pub project_id: ProjectId,
    pub agent_id: AgentId,
    pub agent_name: String,
    pub peer_pid: u32,
    pub delivery: oneshot::Sender<ClaimApprovalDelivery>,
    pub bridge: Arc<Mutex<crate::runtime::admission::external::BridgeBinding>>,
}

#[derive(Clone, Debug)]
pub(crate) struct ActiveLease {
    pub project_id: ProjectId,
    pub agent_id: AgentId,
    pub agent_name: String,
    pub session_id: SessionId,
    pub credential_id: se_store::RecordId,
    pub lease_generation: u64,
    pub peer_pid: u32,
    pub host_generation: Generation,
    pub expires_at_us: i64,
    /// Set when an indeterminate approval or failed rollback must be reconciled
    /// against durable store state before the slot can be treated as healthy.
    pub reconcile_required: bool,
}

/// Tracks pending claims and active external seat leases for this host generation.
pub(crate) struct ExternalRegistry {
    next_lease_generation: AtomicU64,
    state: Mutex<RegistryState>,
}

#[derive(Default)]
struct RegistryState {
    pending: BTreeMap<String, PendingClaimEntry>,
    active: BTreeMap<(ProjectId, AgentId), ActiveLease>,
    receivers: BTreeMap<String, ClaimReceiver>,
    agent_locks: BTreeMap<(ProjectId, AgentId), Arc<tokio::sync::Mutex<()>>>,
}

impl Default for ExternalRegistry {
    fn default() -> Self {
        Self {
            next_lease_generation: AtomicU64::new(1),
            state: Mutex::new(RegistryState::default()),
        }
    }
}

/// Inputs required to open a pending external seat claim.
pub(crate) struct NewClaim {
    pub project_id: ProjectId,
    pub agent_id: AgentId,
    pub agent_name: String,
    pub peer_binding: Vec<u8>,
    pub peer_pid: u32,
    pub connection_nonce: [u8; 32],
    pub host_generation: Generation,
    pub now_us: i64,
    pub bridge: Arc<Mutex<crate::runtime::admission::external::BridgeBinding>>,
}

impl ExternalRegistry {
    /// Per-`(project_id, agent_id)` async mutex serializing approve, revoke,
    /// expiry reconciliation, and fenced disconnect from preflight through publication.
    pub(crate) fn agent_lock(
        &self,
        project_id: &ProjectId,
        agent_id: &AgentId,
    ) -> Result<Arc<tokio::sync::Mutex<()>>> {
        let mut guard = self.state.lock().map_err(|_| poisoned())?;
        Ok(Arc::clone(
            guard
                .agent_locks
                .entry((project_id.clone(), agent_id.clone()))
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        ))
    }

    pub(crate) fn allocate_lease_generation(&self) -> u64 {
        self.next_lease_generation.fetch_add(1, Ordering::AcqRel)
    }

    pub(crate) fn open_claim(&self, new: NewClaim) -> Result<PendingClaimHandle> {
        let NewClaim {
            project_id,
            agent_id,
            agent_name,
            peer_binding,
            peer_pid,
            connection_nonce,
            host_generation,
            now_us,
            bridge,
        } = new;
        let mut guard = self.state.lock().map_err(|_| poisoned())?;
        prune_expired(&mut guard);
        if guard.pending.len() >= MAX_PENDING_CLAIMS {
            return Err(SeError::invalid(
                "external seat claims",
                "fewer pending claims; approve or let stale claims expire before opening another",
            ));
        }
        let nonce = crate::client::auth::fresh_nonce()?;
        let claim_id = format!("claim_{}", se_types::hex_lower(&nonce[..16]));
        let expires_at = Instant::now() + Duration::from_secs(CLAIM_TTL_SECS);
        let expires_at_us = now_us
            .checked_add((CLAIM_TTL_SECS as i64) * 1_000_000)
            .ok_or_else(|| SeError::invalid("claim expiry", "clock overflow"))?;
        let (tx, rx) = oneshot::channel();
        let entry = PendingClaimEntry {
            claim_id: claim_id.clone(),
            project_id: project_id.clone(),
            agent_id: agent_id.clone(),
            agent_name: agent_name.clone(),
            scope: EXTERNAL_SEAT_SCOPE.to_owned(),
            peer_pid,
            host_generation,
            expires_at,
            expires_at_us,
            delivery: tx,
            bridge,
        };
        let receiver = ClaimReceiver {
            peer_binding: peer_binding.clone(),
            connection_nonce,
            host_generation,
            expires_at,
            approved: false,
            rx,
        };
        guard.pending.insert(claim_id.clone(), entry);
        guard.receivers.insert(claim_id.clone(), receiver);
        Ok(PendingClaimHandle {
            claim_id,
            project_id,
            agent_id,
            agent_name,
            peer_binding,
            connection_nonce,
            host_generation,
            expires_at_us,
        })
    }

    /// Take the waiting bridge's oneshot receiver, verifying exact peer/nonce/generation binding.
    /// Works even if the Owner already approved the claim before `ClaimWait` arrived.
    pub(crate) fn attach_waiter(
        &self,
        claim_id: &str,
        peer_binding: &[u8],
        connection_nonce: &[u8; 32],
        host_generation: Generation,
    ) -> Result<(oneshot::Receiver<ClaimApprovalDelivery>, Instant)> {
        let mut guard = self.state.lock().map_err(|_| poisoned())?;
        prune_expired(&mut guard);
        let receiver = guard.receivers.get(claim_id).ok_or_else(|| {
            SeError::invalid(
                "external claim",
                "an open unexpired pending claim for this connection",
            )
        })?;
        if receiver.peer_binding != peer_binding
            || receiver.connection_nonce != *connection_nonce
            || receiver.host_generation != host_generation
        {
            return Err(SeError::invalid(
                "external claim binding",
                "the exact bridge process, nonce, and host generation that opened this claim",
            ));
        }
        let receiver = guard.receivers.remove(claim_id).ok_or_else(|| {
            SeError::invalid(
                "external claim",
                "an open unexpired pending claim for this connection",
            )
        })?;
        Ok((receiver.rx, receiver.expires_at))
    }

    /// Inspect a pending claim without consuming it, verifying existence, generation, and expiry.
    pub(crate) fn peek_claim(
        &self,
        claim_id: &str,
        host_generation: Generation,
    ) -> Result<PeekedClaim> {
        let mut guard = self.state.lock().map_err(|_| poisoned())?;
        prune_expired(&mut guard);
        let entry = guard.pending.get(claim_id).ok_or_else(|| {
            SeError::invalid(
                "external claim",
                "an existing unexpired pending claim; run `se external list` to inspect open claims",
            )
        })?;
        if entry.host_generation != host_generation {
            return Err(SeError::invalid(
                "external claim generation",
                "a claim opened against the current host generation",
            ));
        }
        if Instant::now() >= entry.expires_at {
            return Err(SeError::invalid(
                "external claim",
                "an unexpired pending claim; reconnect the bridge to open a fresh claim",
            ));
        }
        Ok(PeekedClaim {
            project_id: entry.project_id.clone(),
            agent_id: entry.agent_id.clone(),
        })
    }

    /// Consume a pending claim at most once. Fails closed on absence, expiry, or generation mismatch.
    pub(crate) fn consume_claim(
        &self,
        claim_id: &str,
        host_generation: Generation,
    ) -> Result<ConsumedClaim> {
        let mut guard = self.state.lock().map_err(|_| poisoned())?;
        prune_expired(&mut guard);
        let entry = guard.pending.remove(claim_id).ok_or_else(|| {
            SeError::invalid(
                "external claim",
                "an existing unexpired pending claim; run `se external list` to inspect open claims",
            )
        })?;
        if entry.host_generation != host_generation {
            return Err(SeError::invalid(
                "external claim generation",
                "a claim opened against the current host generation",
            ));
        }
        if Instant::now() >= entry.expires_at {
            return Err(SeError::invalid(
                "external claim",
                "an unexpired pending claim; reconnect the bridge to open a fresh claim",
            ));
        }
        if let Some(receiver) = guard.receivers.get_mut(&entry.claim_id) {
            receiver.approved = true;
        }
        Ok(ConsumedClaim {
            claim_id: entry.claim_id,
            project_id: entry.project_id,
            agent_id: entry.agent_id,
            agent_name: entry.agent_name,
            peer_pid: entry.peer_pid,
            delivery: entry.delivery,
            bridge: entry.bridge,
        })
    }

    /// Cancel a pending claim and return any already-approved delivery that had
    /// not yet been collected by `ClaimWait` so the caller can durably revoke it.
    pub(crate) fn cancel_pending_claim(&self, claim_id: &str) -> Option<ClaimApprovalDelivery> {
        let mut guard = self.state.lock().ok()?;
        guard.pending.remove(claim_id);
        let mut receiver = guard.receivers.remove(claim_id)?;
        receiver.rx.try_recv().ok()
    }

    pub(crate) fn record_active_lease(&self, lease: ActiveLease) -> Result<()> {
        let mut guard = self.state.lock().map_err(|_| poisoned())?;
        guard
            .active
            .insert((lease.project_id.clone(), lease.agent_id.clone()), lease);
        Ok(())
    }

    /// Read-only fenced lookup matching exact `(session_id, lease_generation)`.
    pub(crate) fn matching_lease(
        &self,
        project_id: &ProjectId,
        agent_id: &AgentId,
        session_id: &SessionId,
        lease_generation: u64,
    ) -> Result<Option<ActiveLease>> {
        let guard = self.state.lock().map_err(|_| poisoned())?;
        Ok(guard
            .active
            .get(&(project_id.clone(), agent_id.clone()))
            .filter(|lease| {
                lease.session_id == *session_id && lease.lease_generation == lease_generation
            })
            .cloned())
    }

    /// Read-only fenced lookup matching exact `(session_id, lease_generation)` that is healthy and unexpired.
    pub(crate) fn matching_active_lease(
        &self,
        project_id: &ProjectId,
        agent_id: &AgentId,
        session_id: &SessionId,
        lease_generation: u64,
        now_us: i64,
    ) -> Result<Option<ActiveLease>> {
        Ok(self
            .matching_lease(project_id, agent_id, session_id, lease_generation)?
            .filter(|lease| !lease.reconcile_required && lease.expires_at_us > now_us))
    }

    /// Mark an active lease as requiring durable reconciliation (e.g. after a
    /// failed rollback or disconnect cleanup) so it is excluded from healthy
    /// active views and retried on the next reconciliation pass.
    pub(crate) fn mark_reconcile_required(
        &self,
        project_id: &ProjectId,
        agent_id: &AgentId,
        session_id: &SessionId,
        lease_generation: u64,
    ) {
        if let Ok(mut guard) = self.state.lock()
            && let Some(lease) = guard
                .active
                .get_mut(&(project_id.clone(), agent_id.clone()))
            && lease.session_id == *session_id
            && lease.lease_generation == lease_generation
        {
            lease.reconcile_required = true;
        }
    }

    /// Cheap lock check used by `prepare_route` to defer `ProjectStatus`/`AgentShow`
    /// only when an expired or indeterminate external lease requires reconciliation.
    pub(crate) fn has_reconcilable_leases(&self, now_us: i64) -> bool {
        self.state.lock().is_ok_and(|guard| {
            guard
                .active
                .values()
                .any(|lease| lease.reconcile_required || lease.expires_at_us <= now_us)
        })
    }

    /// Fenced removal: removes the active lease ONLY if `(session_id, lease_generation)` matches.
    /// Returns `Some(lease)` if this call won the fence, or `None` if already superseded/revoked.
    pub(crate) fn remove_if_matching(
        &self,
        project_id: &ProjectId,
        agent_id: &AgentId,
        session_id: &SessionId,
        lease_generation: u64,
    ) -> Result<Option<ActiveLease>> {
        let mut guard = self.state.lock().map_err(|_| poisoned())?;
        let key = (project_id.clone(), agent_id.clone());
        let matches = guard.active.get(&key).is_some_and(|lease| {
            lease.session_id == *session_id && lease.lease_generation == lease_generation
        });
        if matches {
            Ok(guard.active.remove(&key))
        } else {
            Ok(None)
        }
    }

    /// Fenced removal by exact `session_id` (never wipes a successor session).
    pub(crate) fn remove_if_session(
        &self,
        project_id: &ProjectId,
        agent_id: &AgentId,
        session_id: &SessionId,
    ) -> Result<Option<ActiveLease>> {
        let mut guard = self.state.lock().map_err(|_| poisoned())?;
        let key = (project_id.clone(), agent_id.clone());
        let matches = guard
            .active
            .get(&key)
            .is_some_and(|lease| lease.session_id == *session_id);
        if matches {
            Ok(guard.active.remove(&key))
        } else {
            Ok(None)
        }
    }

    /// Returns the healthy unexpired active lease for `(project_id, agent_id)`, if any.
    pub(crate) fn active_lease(
        &self,
        project_id: &ProjectId,
        agent_id: &AgentId,
        now_us: i64,
    ) -> Result<Option<ActiveLease>> {
        let guard = self.state.lock().map_err(|_| poisoned())?;
        Ok(guard
            .active
            .get(&(project_id.clone(), agent_id.clone()))
            .filter(|lease| !lease.reconcile_required && lease.expires_at_us > now_us)
            .cloned())
    }

    /// Returns all currently expired or reconcile-required leases still tracked in the registry.
    pub(crate) fn expired_leases(
        &self,
        project: Option<&ProjectId>,
        now_us: i64,
    ) -> Result<Vec<ActiveLease>> {
        let guard = self.state.lock().map_err(|_| poisoned())?;
        Ok(guard
            .active
            .values()
            .filter(|lease| {
                (lease.reconcile_required || lease.expires_at_us <= now_us)
                    && project.is_none_or(|p| &lease.project_id == p)
            })
            .cloned()
            .collect())
    }

    pub(crate) fn list(
        &self,
        project: Option<&ProjectId>,
        now_us: i64,
    ) -> Result<ExternalListOutput> {
        let mut guard = self.state.lock().map_err(|_| poisoned())?;
        prune_expired(&mut guard);
        let pending_claims = guard
            .pending
            .values()
            .filter(|entry| project.is_none_or(|p| &entry.project_id == p))
            .map(|entry| PendingClaimView {
                claim_id: entry.claim_id.clone(),
                project_id: entry.project_id.clone(),
                agent_id: entry.agent_id.clone(),
                agent_name: entry.agent_name.clone(),
                scope: entry.scope.clone(),
                peer_pid: entry.peer_pid,
                host_generation: entry.host_generation,
                expires_at_us: entry.expires_at_us,
            })
            .collect();
        let active_leases = guard
            .active
            .values()
            .filter(|lease| {
                !lease.reconcile_required
                    && lease.expires_at_us > now_us
                    && project.is_none_or(|p| &lease.project_id == p)
            })
            .map(|lease| ActiveExternalLeaseView {
                project_id: lease.project_id.clone(),
                agent_id: lease.agent_id.clone(),
                agent_name: lease.agent_name.clone(),
                session_id: lease.session_id.clone(),
                lease_generation: lease.lease_generation,
                peer_pid: lease.peer_pid,
                host_generation: lease.host_generation,
                expires_at_us: lease.expires_at_us,
            })
            .collect();
        Ok(ExternalListOutput {
            pending_claims,
            active_leases,
        })
    }
}

fn prune_expired(state: &mut RegistryState) {
    let now = Instant::now();
    state.pending.retain(|_, entry| now < entry.expires_at);
    state
        .receivers
        .retain(|_, receiver| now < receiver.expires_at || receiver.approved);
}

fn poisoned() -> SeError {
    se_core::scope::unreadable("external seat registry", "internal lock was poisoned")
}
