//! One owned worker; transient failures retry without needing unrelated mail.
use super::*;
use tokio::time::Instant;

impl Registration {
    fn completed(&mut self, result: api::Result<()>) {
        self.error = result.err();
        if self.error.is_some() {
            self.retry_at = Some(Instant::now() + self.backoff);
            self.backoff = self.backoff.saturating_mul(2).min(Duration::from_secs(30));
        } else {
            self.retry_at = None;
            self.backoff = Duration::from_secs(1);
        }
    }
}
/// Joined by the embedded owner before its writer/lease can close. An idle or
/// sleeping retry holds only the registry, never the Generation strong owner.
pub(in crate::runtime::embedded) async fn drive(
    owner: std::sync::Weak<Generation>,
    router: HostedRouter,
) {
    loop {
        let Some(generation) = owner.upgrade() else {
            return;
        };
        let registry = generation.mail.clone();
        if registry.closed.load(Ordering::Acquire) {
            return;
        }
        let now = Instant::now();
        let (work, next) = match registry.entries.lock() {
            Ok(mut entries) => {
                let mut work = Vec::new();
                let mut next = None;
                for entry in entries.values_mut() {
                    if let Some(at) = entry.retry_at
                        && at > now
                    {
                        next = Some(next.map_or(at, |old: Instant| old.min(at)));
                        continue;
                    }
                    if entry.signal.dirty.swap(false, Ordering::AcqRel) || entry.retry_at.is_some()
                    {
                        entry.retry_at = None;
                        work.push(entry.clone());
                    }
                }
                (work, next)
            }
            Err(_) => {
                generation.poison_now(false);
                return;
            }
        };
        drop(generation);
        if work.is_empty() {
            if let Some(at) = next {
                let _ = tokio::time::timeout_at(at, registry.changed.notified()).await;
            } else {
                registry.changed.notified().await;
            }
            continue;
        }
        for entry in work {
            if registry.closed.load(Ordering::Acquire) {
                return;
            }
            let Some(generation) = owner.upgrade() else {
                return;
            };
            let result = generation
                .protected(
                    "native_mail",
                    false,
                    generation.deliver_native(&router, &entry.target),
                )
                .await;
            match registry.entries.lock() {
                Ok(mut entries) => {
                    if let Some(current) = entries.get_mut(&entry.target.binding.session.0) {
                        current.completed(result);
                    }
                }
                Err(_) => {
                    generation.poison_now(false);
                    return;
                }
            }
        }
    }
}
