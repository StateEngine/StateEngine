//! Core writes fence record-cache freshness before entering the writer queue.
use se_types::{Result, SeError};
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct State {
    serial: u64,
    pending: u32,
    current: Vec<(RecordFeedScope, u64)>,
    interests: Vec<se_types::ProjectId>,
}
/// Each worktree and each replacement epoch owns a different rebuildable feed.
#[derive(Clone, PartialEq, Eq)]
pub struct RecordFeedScope {
    pub project: se_types::ProjectId,
    pub root: se_types::code::RootId,
    pub epoch: se_types::code::CacheEpoch,
}
impl From<&se_atlas::cache::CacheIdentity> for RecordFeedScope {
    fn from(identity: &se_atlas::cache::CacheIdentity) -> Self {
        Self {
            project: identity.scope.registration.project.clone(),
            root: identity.scope.registration.root.clone(),
            epoch: identity.epoch.clone(),
        }
    }
}
#[derive(Default)]
pub struct RecordFeedFence {
    state: Mutex<State>,
    #[cfg(feature = "runtime")]
    changed: tokio::sync::Notify,
}
/// Capture before opening the authoritative query/feed snapshot. A token from
/// an older snapshot cannot certify a newer feed after a concurrent core write.
#[derive(Clone, Copy)]
pub struct RecordFeedTicket(u64);
pub(crate) struct RecordFeedWrite {
    fence: Arc<RecordFeedFence>,
    release: bool,
}
impl RecordFeedWrite {
    /// An unknown commit outcome holds freshness false for this owner lifetime.
    pub(crate) fn uncertain(mut self) {
        self.release = false;
    }
}
impl RecordFeedFence {
    #[cfg(all(feature = "runtime", any(target_os = "linux", test)))]
    pub(crate) async fn changed(&self) {
        self.changed.notified().await;
    }
    #[cfg(all(feature = "runtime", any(target_os = "linux", test)))]
    pub(crate) fn interests(&self) -> Result<Vec<se_types::ProjectId>> {
        Ok(self.lock()?.interests.clone())
    }
    pub(crate) fn before_scoped_write(
        self: &Arc<Self>,
        scope: &se_store::Scope,
    ) -> Result<RecordFeedWrite> {
        let guard = self.before_write()?;
        if let se_store::Scope::Project(project) = scope {
            self.interest(project)?;
        }
        Ok(guard)
    }
    /// Bounded owner interest is not an authoritative write or freshness fence.
    /// Repeated reads of the most recent project do not restart maintenance.
    pub(crate) fn interest(&self, project: &se_types::ProjectId) -> Result<()> {
        let mut state = self.lock()?;
        if state.interests.last() == Some(project) {
            return Ok(());
        }
        state.interests.retain(|p| p != project);
        if state.interests.len() == 2 {
            state.interests.remove(0);
        }
        state.interests.push(project.clone());
        drop(state);
        self.wake_owner();
        Ok(())
    }
    pub(crate) fn wake_owner(&self) {
        #[cfg(feature = "runtime")]
        self.changed.notify_one();
    }
    #[cfg(all(feature = "runtime", target_os = "linux"))]
    pub(crate) fn interested(&self, project: &se_types::ProjectId) -> Result<bool> {
        Ok(self.lock()?.interests.contains(project))
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| {
            SeError::invalid(
                "Atlas record feed",
                "an unpoisoned owner fence; freshness is unknown",
            )
        })
    }
    pub fn ticket(&self) -> Result<Option<RecordFeedTicket>> {
        let state = self.lock()?;
        Ok((state.pending == 0).then_some(RecordFeedTicket(state.serial)))
    }
    /// Call only after the feed transaction from this token's core snapshot
    /// committed. False means a write intervened; retain RecordFeedLag.
    pub fn mark_current(&self, scope: RecordFeedScope, ticket: RecordFeedTicket) -> Result<bool> {
        let mut state = self.lock()?;
        let valid = state.pending == 0 && state.serial == ticket.0;
        if valid {
            state
                .current
                .retain(|(old, _)| old.project != scope.project || old.root != scope.root);
            if state.current.len() == 2 {
                state.current.remove(0);
            }
            state.current.push((scope, ticket.0));
        }
        Ok(valid)
    }
    pub fn is_current(
        &self,
        scope: &RecordFeedScope,
        ticket: Option<RecordFeedTicket>,
    ) -> Result<bool> {
        let state = self.lock()?;
        Ok(ticket.is_some_and(|ticket| {
            state.pending == 0
                && state.serial == ticket.0
                && state
                    .current
                    .iter()
                    .any(|(root, serial)| root == scope && *serial == ticket.0)
        }))
    }
    pub(crate) fn before_write(self: &Arc<Self>) -> Result<RecordFeedWrite> {
        let mut state = self.lock()?;
        state.current.clear();
        let serial = state.serial.checked_add(1).ok_or_else(|| {
            SeError::invalid(
                "Atlas record feed serial",
                "a new owner after serial exhaustion",
            )
        })?;
        let pending = state.pending.checked_add(1).ok_or_else(|| {
            SeError::invalid("Atlas record feed writers", "bounded pending writes")
        })?;
        state.serial = serial;
        state.pending = pending;
        Ok(RecordFeedWrite {
            fence: Arc::clone(self),
            release: true,
        })
    }
}
impl Drop for RecordFeedWrite {
    fn drop(&mut self) {
        // Poison remains a refusal on subsequent observations. Never restore an
        // earlier current claim, even when the write failed or was abandoned.
        if self.release
            && let Ok(mut state) = self.fence.state.lock()
        {
            state.pending -= 1;
        }
        // One coalesced event remains pending when no waiter is armed. A
        // cancelled request's retained completion observer still wakes the owner.
        #[cfg(feature = "runtime")]
        self.fence.changed.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn outstanding_and_intervening_writes_refuse_freshness() -> Result<()> {
        let fence = Arc::new(RecordFeedFence::default());
        let scope = RecordFeedScope {
            project: se_types::ProjectId::from_parts(1, [1; 10])?,
            root: se_types::code::RootId::from_parts(1, [2; 10])?,
            epoch: se_types::code::CacheEpoch::from_parts(1, [3; 10])?,
        };
        let mut second = scope.clone();
        second.root = se_types::code::RootId::from_parts(1, [4; 10])?;
        let initial = fence
            .ticket()?
            .ok_or_else(|| SeError::invalid("test fence", "no writer"))?;
        assert!(!fence.is_current(&scope, Some(initial))?);
        assert!(fence.mark_current(scope.clone(), initial)?);
        assert!(!fence.is_current(&second, Some(initial))?);
        assert!(fence.mark_current(second.clone(), initial)?);
        let mut replacement = scope.clone();
        replacement.epoch = se_types::code::CacheEpoch::from_parts(1, [5; 10])?;
        assert!(!fence.is_current(&replacement, Some(initial))?);
        let write = fence.before_write()?;
        assert!(!fence.is_current(&scope, Some(initial))?);
        assert!(!fence.is_current(&second, Some(initial))?);
        assert!(fence.ticket()?.is_none());
        assert!(!fence.mark_current(scope.clone(), initial)?);
        drop(write);
        assert!(!fence.mark_current(scope.clone(), initial)?);
        let fresh = fence
            .ticket()?
            .ok_or_else(|| SeError::invalid("test fence", "writer settled"))?;
        assert!(!fence.is_current(&scope, Some(fresh))?);
        assert!(fence.mark_current(scope.clone(), fresh)?);
        assert!(fence.is_current(&scope, Some(fresh))?);
        fence.before_write()?.uncertain();
        assert!(fence.ticket()?.is_none());
        assert!(!fence.mark_current(scope, fresh)?);
        Ok(())
    }
}
