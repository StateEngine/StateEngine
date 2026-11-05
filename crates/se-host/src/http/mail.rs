//! One bounded event-driven wait per authenticated session. Notifications are
//! hints: every response rereads current credentials and recipient-scoped mail.
use crate::{HostedRouter, client::lease::Deadline};
use se_types::{ProjectId, Result, SeError, Secret, SessionId};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
pub(crate) mod bell;

pub(crate) struct Waits {
    pub(crate) bells: Arc<bell::Bells>,
    maximum: usize,
    sessions: Mutex<BTreeMap<(ProjectId, SessionId), Arc<Signal>>>,
    // Cancelled predecessors may still be encoding/closing their connection.
    // Bound those retained resources separately from the live session map.
    retained: Arc<Semaphore>,
    closed: AtomicBool,
    native: Mutex<
        Vec<(
            crate::runtime::MailRecipient,
            std::sync::Weak<crate::runtime::mail::NativeSignal>,
        )>,
    >,
}
struct Signal {
    changed: Notify,
    cancelled: AtomicBool,
    recipient: crate::runtime::MailRecipient,
    credential: se_store::RecordId,
}
struct Wait {
    registry: Arc<Waits>,
    key: (ProjectId, SessionId),
    signal: Arc<Signal>,
    _permit: OwnedSemaphorePermit,
}
impl Waits {
    pub(crate) fn new(maximum: usize) -> Arc<Self> {
        Arc::new(Self {
            bells: bell::Bells::new(maximum),
            maximum,
            sessions: Mutex::new(BTreeMap::new()),
            retained: Arc::new(Semaphore::new(maximum.saturating_mul(2))),
            closed: AtomicBool::new(false),
            native: Mutex::new(Vec::new()),
        })
    }
    fn register(
        self: &Arc<Self>,
        session: SessionId,
        recipient: crate::runtime::MailRecipient,
        credential: se_store::RecordId,
    ) -> Result<Wait> {
        let permit = Arc::clone(&self.retained)
            .try_acquire_owned()
            .map_err(|_| {
                SeError::invalid("parked mail capacity", "retry after an earlier wait closes")
            })?;
        let mut sessions = self.sessions.lock().map_err(|_| poisoned())?;
        let key = (recipient.project.clone(), session);
        if self.closed.load(Ordering::Acquire) {
            return Err(SeError::invalid(
                "parked mail",
                "a running host before shutdown",
            ));
        }
        if !sessions.contains_key(&key) && sessions.len() >= self.maximum {
            return Err(SeError::invalid(
                "parked mail capacity",
                "one wait per negotiated session slot",
            ));
        }
        let signal = Arc::new(Signal {
            changed: Notify::new(),
            cancelled: AtomicBool::new(false),
            recipient,
            credential,
        });
        if let Some(previous) = sessions.insert(key.clone(), Arc::clone(&signal)) {
            previous.cancelled.store(true, Ordering::Release);
            previous.changed.notify_one();
        }
        Ok(Wait {
            registry: Arc::clone(self),
            key,
            signal,
            _permit: permit,
        })
    }
    pub(crate) fn committed(&self, recipients: &[crate::runtime::MailRecipient]) -> Result<()> {
        if recipients.is_empty() {
            return Ok(());
        }
        for signal in self.sessions.lock().map_err(|_| poisoned())?.values() {
            if recipients.contains(&signal.recipient) {
                signal.changed.notify_one();
            }
        }
        let mut native = self.native.lock().map_err(|_| poisoned())?;
        native.retain(|(_, signal)| signal.strong_count() > 0);
        for (recipient, signal) in native.iter() {
            if recipients.contains(recipient)
                && let Some(signal) = signal.upgrade()
            {
                signal.wake();
            }
        }
        Ok(())
    }
    #[cfg(feature = "secode")]
    pub(crate) fn register_native(
        &self,
        recipient: crate::runtime::MailRecipient,
        signal: &Arc<crate::runtime::mail::NativeSignal>,
    ) -> Result<()> {
        let mut native = self.native.lock().map_err(|_| poisoned())?;
        native.retain(|(_, signal)| signal.strong_count() > 0);
        if native
            .iter()
            .any(|(_, old)| old.ptr_eq(&Arc::downgrade(signal)))
        {
            return Ok(());
        }
        if self.closed.load(Ordering::Acquire) || native.len() >= self.maximum {
            return Err(SeError::invalid(
                "native mail subscriptions",
                "available session capacity before drain",
            ));
        }
        native.push((recipient, Arc::downgrade(signal)));
        Ok(())
    }
    pub(crate) fn catch_up_native(&self) -> Result<()> {
        for (_, signal) in self.native.lock().map_err(|_| poisoned())?.iter() {
            if let Some(signal) = signal.upgrade() {
                signal.wake();
            }
        }
        Ok(())
    }
    pub(crate) fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::Release);
        for signal in self.sessions.lock().map_err(|_| poisoned())?.values() {
            signal.cancelled.store(true, Ordering::Release);
            signal.changed.notify_one();
        }
        for (_, signal) in self.native.lock().map_err(|_| poisoned())?.iter() {
            if let Some(signal) = signal.upgrade() {
                signal.wake();
            }
        }
        Ok(())
    }
    pub(crate) fn interrupt(&self, session: &SessionId) -> Result<()> {
        for ((_, found), signal) in self.sessions.lock().map_err(|_| poisoned())?.iter() {
            if found == session {
                signal.cancelled.store(true, Ordering::Release);
                signal.changed.notify_one();
            }
        }
        Ok(())
    }
    pub(crate) fn revoked(&self, changes: &crate::runtime::mail::Revocations) -> Result<()> {
        if changes.sessions.is_empty() && changes.credentials.is_empty() {
            return Ok(());
        }
        for (_, session) in &changes.sessions {
            self.bells.revoke(session)?;
        }
        for ((project, session), signal) in self.sessions.lock().map_err(|_| poisoned())?.iter() {
            if changes
                .sessions
                .iter()
                .any(|(found_project, found)| found_project == project && found == session)
                || changes.credentials.iter().any(|(project, found)| {
                    project == &signal.recipient.project && *found == signal.credential
                })
            {
                self.bells.revoke(session)?;
                signal.changed.notify_one();
            }
        }
        Ok(())
    }
}
impl Drop for Wait {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.registry.sessions.lock()
            && sessions
                .get(&self.key)
                .is_some_and(|signal| Arc::ptr_eq(signal, &self.signal))
        {
            sessions.remove(&self.key);
        }
    }
}
fn poisoned() -> SeError {
    se_core::scope::unreadable("parked mail registry", "session registry is poisoned")
}

#[derive(serde::Serialize)]
pub(crate) struct Page {
    #[serde(skip)]
    pub session: SessionId,
    #[serde(skip)]
    pub recipient: crate::runtime::MailRecipient,
    #[serde(skip)]
    pub credential: se_store::RecordId,
    pub ids: Vec<se_types::MessageId>,
    pub cursor: se_types::Cursor,
    pub complete: bool,
}
impl HostedRouter {
    async fn mail_page(&self, secret: Arc<Secret>, deadline: &Deadline) -> Result<Page> {
        self.check_open()?;
        let context = self.context.clone();
        self.execution
            .blocking
            .run_owned(deadline, move || context.mail_page(&secret))
            .await
    }
    pub(crate) async fn next_mail(
        &self,
        secret: Arc<Secret>,
        after: Option<String>,
        active: Arc<Mutex<Option<OwnedSemaphorePermit>>>,
        deadline: &Deadline,
    ) -> Result<Page> {
        let bounded = deadline.stage(Duration::from_secs(25))?;
        let deadline = &bounded;
        let until = tokio::time::Instant::from_std(deadline.at() - Duration::from_secs(1));
        let first = self.mail_page(Arc::clone(&secret), deadline).await?;
        if self.execution.mail_waits.bells.held(&first.session)? {
            return Err(SeError::invalid(
                "Claude mail hold",
                "explicit /stateengine-mail-resume; new mail or reconnect never clears a human hold",
            ));
        }
        // Subscribe before the deciding read so a committed change cannot fall
        // between the snapshot and installing the event waiter.
        let wait =
            self.execution
                .mail_waits
                .register(first.session, first.recipient, first.credential)?;
        active.lock().map_err(|_| poisoned())?.take();
        loop {
            if wait.signal.cancelled.load(Ordering::Acquire) {
                return Err(SeError::invalid(
                    "parked mail",
                    "this session's current wait; replaced or stopped",
                ));
            }
            let page = self.mail_page(Arc::clone(&secret), deadline).await?;
            if self.execution.mail_waits.bells.held(&page.session)? {
                return Err(SeError::invalid(
                    "Claude mail hold",
                    "explicit /stateengine-mail-resume",
                ));
            }
            if !page.ids.is_empty() && after.as_deref() != Some(page.cursor.as_str()) {
                return Ok(page);
            }
            if tokio::time::timeout_at(until, wait.signal.changed.notified())
                .await
                .is_err()
            {
                // Revocation/expiry and final inbox state are rechecked even on
                // timeout. The GET never marks any message read or delivered.
                return self.mail_page(secret, deadline).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use se_store::RecordIdentity;
    fn recipient() -> Result<crate::runtime::MailRecipient> {
        Ok(crate::runtime::MailRecipient {
            project: se_types::ProjectId::from_parts(1, [1; 10])?,
            agent: se_types::AgentId::from_parts(1, [2; 10])?,
        })
    }
    fn credential(n: u8) -> Result<se_store::RecordId> {
        let mut bytes = [n; 16];
        bytes[6] = 0x70 | (n & 0x0f);
        bytes[8] = 0x80 | (n & 0x3f);
        se_store::RecordId::from_bytes(bytes)
            .map_err(|error| se_core::store_error::store_error(&error))
    }
    #[test]
    fn revocations_wake_only_the_bound_session_or_credential_in_its_project() -> Result<()> {
        use std::{
            future::Future,
            task::{Context, Waker},
        };
        let registry = Waits::new(3);
        let own = recipient()?;
        let foreign = crate::runtime::MailRecipient {
            project: ProjectId::from_parts(1, [8; 10])?,
            agent: own.agent.clone(),
        };
        let session = SessionId::from_parts(1, [4; 10])?;
        let second_session = SessionId::from_parts(1, [5; 10])?;
        let first = registry.register(session.clone(), own.clone(), credential(1)?)?;
        let second = registry.register(second_session.clone(), own.clone(), credential(2)?)?;
        let other = registry.register(session, foreign, credential(1)?)?;
        assert!(!first.signal.cancelled.load(Ordering::Acquire));
        let mut context = Context::from_waker(Waker::noop());
        let mut a = Box::pin(first.signal.changed.notified());
        let mut b = Box::pin(second.signal.changed.notified());
        let mut c = Box::pin(other.signal.changed.notified());
        assert!(a.as_mut().poll(&mut context).is_pending());
        assert!(b.as_mut().poll(&mut context).is_pending());
        assert!(c.as_mut().poll(&mut context).is_pending());
        registry.revoked(&crate::runtime::mail::Revocations {
            sessions: vec![],
            credentials: vec![(own.project.clone(), credential(1)?)],
        })?;
        assert!(a.as_mut().poll(&mut context).is_ready());
        assert!(b.as_mut().poll(&mut context).is_pending());
        assert!(c.as_mut().poll(&mut context).is_pending());
        let mut again = Box::pin(first.signal.changed.notified());
        assert!(again.as_mut().poll(&mut context).is_pending());
        registry.revoked(&crate::runtime::mail::Revocations {
            sessions: vec![(own.project, second_session)],
            credentials: vec![],
        })?;
        assert!(again.as_mut().poll(&mut context).is_pending());
        assert!(b.as_mut().poll(&mut context).is_ready());
        assert!(c.as_mut().poll(&mut context).is_pending());
        Ok(())
    }
    #[test]
    fn commits_wake_only_sessions_for_the_exact_recipient() -> Result<()> {
        use std::{
            future::Future,
            task::{Context, Waker},
        };
        let registry = Waits::new(3);
        let own = recipient()?;
        let foreign = crate::runtime::MailRecipient {
            project: se_types::ProjectId::from_parts(1, [3; 10])?,
            agent: own.agent.clone(),
        };
        let first = registry.register(
            SessionId::from_parts(1, [4; 10])?,
            own.clone(),
            credential(1)?,
        )?;
        let second = registry.register(
            SessionId::from_parts(1, [5; 10])?,
            own.clone(),
            credential(1)?,
        )?;
        let other =
            registry.register(SessionId::from_parts(1, [6; 10])?, foreign, credential(2)?)?;
        let mut context = Context::from_waker(Waker::noop());
        registry.committed(&[])?;
        let mut a = Box::pin(first.signal.changed.notified());
        let mut b = Box::pin(second.signal.changed.notified());
        let mut c = Box::pin(other.signal.changed.notified());
        assert!(a.as_mut().poll(&mut context).is_pending());
        assert!(b.as_mut().poll(&mut context).is_pending());
        assert!(c.as_mut().poll(&mut context).is_pending());
        registry.committed(&[own])?;
        assert!(a.as_mut().poll(&mut context).is_ready());
        assert!(b.as_mut().poll(&mut context).is_ready());
        assert!(c.as_mut().poll(&mut context).is_pending());
        Ok(())
    }
    #[test]
    fn replacement_cancels_only_its_predecessor_and_keeps_capacity_bounded() -> Result<()> {
        let registry = Waits::new(1);
        let session = SessionId::from_parts(1, [1; 10])?;
        let other = SessionId::from_parts(1, [2; 10])?;
        let first = registry.register(session.clone(), recipient()?, credential(1)?)?;
        assert!(
            registry
                .register(other.clone(), recipient()?, credential(1)?)
                .is_err()
        );
        let second = registry.register(session.clone(), recipient()?, credential(1)?)?;
        assert!(first.signal.cancelled.load(Ordering::Acquire));
        assert!(!second.signal.cancelled.load(Ordering::Acquire));
        assert!(
            registry
                .register(session.clone(), recipient()?, credential(1)?)
                .is_err()
        );
        drop(first);
        assert!(
            registry
                .register(other.clone(), recipient()?, credential(1)?)
                .is_err()
        );
        assert_eq!(registry.retained.available_permits(), 1);
        drop(second);
        let last = registry.register(other, recipient()?, credential(1)?)?;
        registry.close()?;
        assert!(last.signal.cancelled.load(Ordering::Acquire));
        assert!(
            registry
                .register(session, recipient()?, credential(1)?)
                .is_err()
        );
        drop(last);
        assert_eq!(registry.retained.available_permits(), 2);
        Ok(())
    }
}
