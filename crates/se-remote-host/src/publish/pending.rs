//! Bounded producer handoff; the ring owner drains without another task/timer.
use super::*;

pub(super) struct Pending {
    pub source: Arc<Source>,
    pub item: RemoteLiveItem,
    pub digest: [u8; 32],
    pub complete: bool,
    pub observed_at: Instant,
}
impl State {
    pub(super) fn drain_pending(&mut self) {
        // Bound each critical section even while producers continue enqueueing.
        for _ in 0..PENDING_OBSERVATIONS {
            let Some(receiver) = &self.pending else {
                break;
            };
            let Ok(pending) = receiver.try_recv() else {
                break;
            };
            self.insert(pending);
        }
    }
    fn insert(&mut self, pending: Pending) {
        let Pending {
            source,
            item,
            digest,
            complete,
            observed_at,
        } = pending;
        if source.broken.load(Ordering::Acquire) || !source.active.load(Ordering::Acquire) {
            return;
        }
        if self.ring.iter().rev().any(|entry| {
            !entry.replaceable
                && entry.observation.position.target == source.stamp.target
                && entry.observation.position.session == source.stamp.session
                && entry.observation.position.lifecycle == source.stamp.lifecycle
                && entry.observation.item.item_id == item.item_id
                && (!complete || entry.digest == digest)
        }) {
            return;
        }
        let Ok(previous) = source
            .sequence
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
        else {
            source.broken.store(true, Ordering::Release);
            source.lost();
            return;
        };
        let mut position = source.stamp.clone();
        position.sequence = previous + 1;
        position.loss = source.loss.load(Ordering::Acquire);
        let observation = Arc::new(Observation {
            position,
            item,
            observed_at,
        });
        let bytes = observation.item.preview.text.len() + observation.item.item_id.len() + 1024;
        let mut first = observation.position.sequence;
        // Keep the existing 16 ms same-item tail coalescing rule.
        if !complete
            && self.ring.back().is_some_and(|last| {
                last.observation.position.target == observation.position.target
                    && last.observation.position.session == observation.position.session
                    && last.observation.item.item_id == observation.item.item_id
                    && last.replaceable
                    && last.observation.observed_at.elapsed() <= Duration::from_millis(16)
            })
            && let Some(last) = self.ring.pop_back()
        {
            first = last.first;
            self.bytes = self.bytes.saturating_sub(last.bytes);
        }
        while bytes > REMOTE_LIVE_RING_BYTES.saturating_sub(self.bytes) {
            if let Some(old) = self.ring.pop_front() {
                self.bytes = self.bytes.saturating_sub(old.bytes);
            } else {
                break;
            }
        }
        self.bytes += bytes;
        self.ring.push_back(Entry {
            observation,
            bytes,
            first,
            replaceable: !complete,
            digest,
        });
    }
}
