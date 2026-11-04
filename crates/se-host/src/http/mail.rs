//! One bounded event-driven wait per authenticated session. Notifications are
//! hints: every response rereads current credentials and recipient-scoped mail.
use crate::{HostedRouter, client::lease::Deadline};
use se_types::{Result, SeError, Secret, SessionId};
use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

pub(crate) struct Waits {
    maximum: usize,
    sessions: Mutex<BTreeMap<SessionId, Arc<Signal>>>,
    // Cancelled predecessors may still be encoding/closing their connection.
    // Bound those retained resources separately from the live session map.
    retained: Arc<Semaphore>,
    closed: AtomicBool,
}
struct Signal {
    changed: Notify,
    cancelled: AtomicBool,
    recipient: crate::runtime::MailRecipient,
}
struct Wait {
    registry: Arc<Waits>,
    session: SessionId,
    signal: Arc<Signal>,
    _permit: OwnedSemaphorePermit,
}
impl Waits {
    pub(crate) fn new(maximum: usize) -> Arc<Self> {
        Arc::new(Self {
            maximum,
            sessions: Mutex::new(BTreeMap::new()),
            retained: Arc::new(Semaphore::new(maximum.saturating_mul(2))),
            closed: AtomicBool::new(false),
        })
    }
    fn register(
        self: &Arc<Self>,
        session: SessionId,
        recipient: crate::runtime::MailRecipient,
    ) -> Result<Wait> {
        let permit = Arc::clone(&self.retained)
            .try_acquire_owned()
            .map_err(|_| {
                SeError::invalid("parked mail capacity", "retry after an earlier wait closes")
            })?;
        let mut sessions = self.sessions.lock().map_err(|_| poisoned())?;
        if self.closed.load(Ordering::Acquire) {
            return Err(SeError::invalid(
                "parked mail",
                "a running host before shutdown",
            ));
        }
        if !sessions.contains_key(&session) && sessions.len() >= self.maximum {
            return Err(SeError::invalid(
                "parked mail capacity",
                "one wait per negotiated session slot",
            ));
        }
        let signal = Arc::new(Signal {
            changed: Notify::new(),
            cancelled: AtomicBool::new(false),
            recipient,
        });
        if let Some(previous) = sessions.insert(session.clone(), Arc::clone(&signal)) {
            previous.cancelled.store(true, Ordering::Release);
            previous.changed.notify_one();
        }
        Ok(Wait {
            registry: Arc::clone(self),
            session,
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
        Ok(())
    }
    pub(crate) fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::Release);
        for signal in self.sessions.lock().map_err(|_| poisoned())?.values() {
            signal.cancelled.store(true, Ordering::Release);
            signal.changed.notify_one();
        }
        Ok(())
    }
}
impl Drop for Wait {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.registry.sessions.lock()
            && sessions
                .get(&self.session)
                .is_some_and(|signal| Arc::ptr_eq(signal, &self.signal))
        {
            sessions.remove(&self.session);
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
        // Subscribe before the deciding read so a committed change cannot fall
        // between the snapshot and installing the event waiter.
        let wait = self
            .execution
            .mail_waits
            .register(first.session, first.recipient)?;
        active.lock().map_err(|_| poisoned())?.take();
        loop {
            if wait.signal.cancelled.load(Ordering::Acquire) {
                return Err(SeError::invalid(
                    "parked mail",
                    "this session's current wait; replaced or stopped",
                ));
            }
            let page = self.mail_page(Arc::clone(&secret), deadline).await?;
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
    fn recipient() -> Result<crate::runtime::MailRecipient> {
        Ok(crate::runtime::MailRecipient {
            project: se_types::ProjectId::from_parts(1, [1; 10])?,
            agent: se_types::AgentId::from_parts(1, [2; 10])?,
        })
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
        let first = registry.register(SessionId::from_parts(1, [4; 10])?, own.clone())?;
        let second = registry.register(SessionId::from_parts(1, [5; 10])?, own.clone())?;
        let other = registry.register(SessionId::from_parts(1, [6; 10])?, foreign)?;
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
        let first = registry.register(session.clone(), recipient()?)?;
        assert!(registry.register(other.clone(), recipient()?).is_err());
        let second = registry.register(session.clone(), recipient()?)?;
        assert!(first.signal.cancelled.load(Ordering::Acquire));
        assert!(!second.signal.cancelled.load(Ordering::Acquire));
        assert!(registry.register(session.clone(), recipient()?).is_err());
        drop(first);
        assert!(registry.register(other.clone(), recipient()?).is_err());
        assert_eq!(registry.retained.available_permits(), 1);
        drop(second);
        let last = registry.register(other, recipient()?)?;
        registry.close()?;
        assert!(last.signal.cancelled.load(Ordering::Acquire));
        assert!(registry.register(session, recipient()?).is_err());
        drop(last);
        assert_eq!(registry.retained.available_permits(), 2);
        Ok(())
    }
}
