//! Attributed pre-COMMIT observations. Producers never wait on a client or store.
use super::*;
use se_types::{Generation, LifecycleId, Omission, OmissionReason, SeError, SessionId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

const PREVIEW_BYTES: usize = 4096;
// At most 64 bounded observations wait for the ring lock (under 512 KiB).
const PENDING_OBSERVATIONS: usize = 64;
mod pending;
use pending::Pending;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LivePosition {
    pub instance: RemoteInstanceId,
    pub publisher: [u8; 16],
    pub target: RemoteTarget,
    pub session: SessionId,
    pub lifecycle: LifecycleId,
    pub generation: Generation,
    pub sequence: u64,
    pub loss: u64,
}
#[derive(Clone, Debug)]
pub struct Observation {
    pub(crate) position: LivePosition,
    pub item: RemoteLiveItem,
    pub observed_at: Instant,
}
struct Entry {
    observation: Arc<Observation>,
    bytes: usize,
    first: u64,
    replaceable: bool,
    digest: [u8; 32],
}
struct State {
    sources: BTreeMap<RemoteTarget, Weak<Source>>,
    ring: VecDeque<Entry>,
    bytes: usize,
    pending: Option<std::sync::mpsc::Receiver<Pending>>,
}
pub(crate) struct LiveRead {
    pub items: Vec<Arc<Observation>>,
    pub position: Option<LivePosition>,
    pub gap: bool,
    pub more: bool,
    pub available: bool,
}
pub struct LivePublisher {
    clock_origin: Instant,
    instance: RemoteInstanceId,
    epoch: [u8; 16],
    state: Mutex<State>,
    pending: std::sync::mpsc::SyncSender<Pending>,
    changed: tokio::sync::Notify,
    committed: AtomicU64,
}
#[derive(Clone)]
pub struct LiveSource(Arc<Source>);
struct Source {
    publisher: Weak<LivePublisher>,
    stamp: LivePosition,
    sequence: AtomicU64,
    loss: AtomicU64,
    broken: AtomicBool,
    active: AtomicBool,
    current: Mutex<VecDeque<(String, String, u64)>>,
}
impl LivePublisher {
    /// A fresh view excludes retained observations from before its attachment.
    pub(crate) fn checkpoint(&self, target: &RemoteTarget) -> Result<Option<LivePosition>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SeError::invalid("live snapshot", "unpoisoned host observation state"))?;
        state.drain_pending();
        let Some(source) = state.sources.get(target).and_then(Weak::upgrade) else {
            return Ok(None);
        };
        let mut position = source.stamp.clone();
        position.sequence = source.sequence.load(Ordering::Acquire);
        position.loss = source.loss.load(Ordering::Acquire);
        Ok(Some(position))
    }

    pub(crate) fn fence(&self) -> Result<()> {
        let (mut state, poisoned) = match self.state.lock() {
            Ok(state) => (state, false),
            Err(error) => (error.into_inner(), true),
        };
        for source in state.sources.values().filter_map(Weak::upgrade) {
            source.active.store(false, Ordering::Release);
        }
        state.ring.clear();
        state.sources.clear();
        state.bytes = 0;
        // Disconnect before releasing the fence, including a producer that
        // passed its active check just before this retirement.
        drop(state.pending.take());
        drop(state);
        self.changed.notify_waiters();
        if poisoned {
            Err(SeError::invalid(
                "remote publisher fence",
                "unpoisoned host state; retired observations require an owning-host restart",
            ))
        } else {
            Ok(())
        }
    }
    pub fn new(instance: RemoteInstanceId) -> Result<Arc<Self>> {
        let (pending, receiver) = std::sync::mpsc::sync_channel(PENDING_OBSERVATIONS);
        Ok(Arc::new(Self {
            clock_origin: Instant::now(),
            instance,
            epoch: session::entropy()?,
            state: Mutex::new(State {
                sources: BTreeMap::new(),
                ring: VecDeque::new(),
                bytes: 0,
                pending: Some(receiver),
            }),
            pending,
            changed: tokio::sync::Notify::new(),
            committed: AtomicU64::new(0),
        }))
    }
    pub(crate) fn clock(&self) -> Result<RemoteObservationClock> {
        Ok(RemoteObservationClock {
            epoch: self.epoch,
            sampled_at_us: self.clock_us(Instant::now())?,
            source_bracket_us: None,
            source_released_at_us: None,
        })
    }
    pub(crate) fn clock_us(&self, observed: Instant) -> Result<i64> {
        let (negative, duration) = match observed.checked_duration_since(self.clock_origin) {
            Some(duration) => (false, duration),
            None => (true, self.clock_origin.duration_since(observed)),
        };
        let us = i64::try_from(duration.as_micros()).map_err(|_| {
            SeError::invalid("observation clock", "a representable monotonic interval")
        })?;
        Ok(if negative { -us } else { us })
    }
    /// Only owned native launch/re-adoption and pinned capture call this seam.
    /// No remote/wire caller can register a producer or supply its attribution.
    pub fn register(
        self: &Arc<Self>,
        target: RemoteTarget,
        session: SessionId,
        lifecycle: LifecycleId,
        generation: Generation,
    ) -> Result<LiveSource> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SeError::invalid("live publisher", "unpoisoned host observation state"))?;
        state.sources.retain(|_, v| v.strong_count() > 0);
        if let Some(existing) = state.sources.get(&target).and_then(Weak::upgrade) {
            if existing.stamp.session == session
                && existing.stamp.lifecycle == lifecycle
                && existing.stamp.generation == generation
            {
                return Ok(LiveSource(existing));
            }
            existing.active.store(false, Ordering::Release);
        }
        if !state.sources.contains_key(&target) && state.sources.len() >= REMOTE_MAX_TARGETS {
            return Err(SeError::invalid(
                "live producer capacity",
                "at most64 attributed agent streams",
            ));
        }
        let source = Arc::new(Source {
            publisher: Arc::downgrade(self),
            stamp: LivePosition {
                instance: self.instance,
                publisher: self.epoch,
                target: target.clone(),
                session,
                lifecycle,
                generation,
                sequence: 0,
                loss: 0,
            },
            sequence: AtomicU64::new(0),
            loss: AtomicU64::new(0),
            broken: AtomicBool::new(false),
            active: AtomicBool::new(true),
            current: Mutex::new(VecDeque::new()),
        });
        state.sources.insert(target, Arc::downgrade(&source));
        Ok(LiveSource(source))
    }
    pub(crate) fn read(
        &self,
        target: &RemoteTarget,
        after: Option<&LivePosition>,
        budget: usize,
    ) -> Result<LiveRead> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SeError::invalid("live replay", "unpoisoned host observation state"))?;
        state.drain_pending();
        let Some(source) = state.sources.get(target).and_then(Weak::upgrade) else {
            return Ok(LiveRead {
                items: vec![],
                position: None,
                gap: after.is_some(),
                more: false,
                available: false,
            });
        };
        let mut position = source.stamp.clone();
        position.sequence = source.sequence.load(Ordering::Acquire);
        position.loss = source.loss.load(Ordering::Acquire);
        let same = after.is_some_and(|old| {
            old.instance == position.instance
                && old.publisher == position.publisher
                && old.target == position.target
                && old.session == position.session
                && old.lifecycle == position.lifecycle
                && old.generation == position.generation
        });
        let matching = state.ring.iter().filter(|entry| {
            entry.observation.position.target == *target
                && entry.observation.position.session == position.session
                && entry.observation.position.lifecycle == position.lifecycle
                && entry.observation.position.generation == position.generation
        });
        let oldest = matching.clone().next().map(|e| e.first);
        let gap = (after.is_none() && (position.loss > 0 || oldest.is_some_and(|first| first > 1)))
            || source.broken.load(Ordering::Acquire)
            || after.is_some_and(|old| {
                !same
                    || old.sequence > position.sequence
                    || old.loss != position.loss
                    || oldest.is_some_and(|first| old.sequence.saturating_add(1) < first)
            });
        let from = after.filter(|_| same).map_or(0, |p| p.sequence);
        let mut bytes = 0;
        let mut items = vec![];
        let mut more = false;
        // The continuation advances only over returned observations, never hidden/global positions.
        let mut next = after.filter(|_| same).cloned().unwrap_or_else(|| {
            let mut p = position.clone();
            p.sequence = 0;
            p
        });
        for entry in matching.filter(|e| e.observation.position.sequence > from) {
            if entry.bytes > budget.saturating_sub(bytes) {
                more = true;
                break;
            }
            bytes += entry.bytes;
            next = entry.observation.position.clone();
            items.push(entry.observation.clone());
        }
        next.loss = position.loss;
        Ok(LiveRead {
            items,
            position: Some(next),
            gap,
            more,
            available: true,
        })
    }
    pub(crate) fn complete_existing(
        &self,
        target: &RemoteTarget,
        session: &SessionId,
        item_id: &str,
        role: RemoteTurnRole,
        text: &str,
        observed_at: Instant,
    ) {
        let source = self
            .state
            .lock()
            .ok()
            .and_then(|state| state.sources.get(target).and_then(Weak::upgrade));
        if let Some(source) = source
            && source.stamp.session == *session
        {
            LiveSource(source).complete_at(item_id, role, text, observed_at);
        }
    }
    pub(crate) fn changed(&self) -> tokio::sync::futures::Notified<'_> {
        self.changed.notified()
    }
    pub(crate) fn committed(&self) {
        // A revision is a scheduling hint, never an authorization or cursor.
        // Saturation keeps readers conservative instead of wrapping to an old cut.
        let _ = self
            .committed
            .fetch_update(Ordering::Release, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1))
            });
        self.changed.notify_waiters();
    }
    pub(crate) fn commit_revision(&self) -> u64 {
        self.committed.load(Ordering::Acquire)
    }
}
impl LiveSource {
    pub fn complete(&self, item_id: &str, role: RemoteTurnRole, text: &str) {
        self.complete_at(item_id, role, text, Instant::now());
    }
    pub(crate) fn complete_at(
        &self,
        item_id: &str,
        role: RemoteTurnRole,
        text: &str,
        observed_at: Instant,
    ) {
        self.emit(item_id, role, text, true, 0, observed_at);
        if let Ok(mut current) = self.0.current.try_lock() {
            current.retain(|(id, _, _)| id != item_id);
        }
    }
    pub fn delta(&self, item_id: &str, role: RemoteTurnRole, delta: &str) {
        self.delta_at(item_id, role, delta, Instant::now());
    }
    pub(crate) fn delta_at(
        &self,
        item_id: &str,
        role: RemoteTurnRole,
        delta: &str,
        observed_at: Instant,
    ) {
        if item_id.is_empty() || item_id.len() > 2048 || item_id.chars().any(char::is_control) {
            self.0.lost();
            return;
        }
        let Ok(mut current) = self.0.current.try_lock() else {
            self.0.lost();
            return;
        };
        if let Some(at) = current.iter().position(|(id, _, _)| id == item_id) {
            let Some((_, text, omitted)) = current.get_mut(at) else {
                self.0.lost();
                return;
            };
            append(text, omitted, delta);
            self.emit(item_id, role, text, false, *omitted, observed_at);
        } else {
            if current.len() == 2 {
                current.pop_front();
                self.0.lost();
            }
            let mut text = String::new();
            let mut omitted = 0;
            append(&mut text, &mut omitted, delta);
            self.emit(item_id, role, &text, false, omitted, observed_at);
            current.push_back((item_id.into(), text, omitted));
        }
    }
    fn emit(
        &self,
        item_id: &str,
        role: RemoteTurnRole,
        text: &str,
        complete: bool,
        prior_omitted: u64,
        observed_at: Instant,
    ) {
        if self.0.broken.load(Ordering::Acquire) || !self.0.active.load(Ordering::Acquire) {
            return;
        }
        if item_id.is_empty() || item_id.len() > 2048 || item_id.chars().any(char::is_control) {
            self.0.lost();
            return;
        }
        let mut hasher = Sha256::new();
        hasher.update([match role {
            RemoteTurnRole::User => 1,
            RemoteTurnRole::Assistant => 2,
            RemoteTurnRole::Tool => 3,
        }]);
        hasher.update(text.as_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        let Some(publisher) = self.0.publisher.upgrade() else {
            return;
        };
        let length = prefix(text, PREVIEW_BYTES);
        let omitted = prior_omitted.saturating_add((text.len() - length) as u64);
        let item = RemoteLiveItem {
            item_id: item_id.into(),
            role,
            preview: RemotePreview {
                text: text[..length].into(),
                complete: complete && omitted == 0,
                omitted_utf8_bytes: std::num::NonZeroU64::new(omitted).map_or(
                    Omission::None,
                    |count| Omission::Known {
                        count,
                        reason: OmissionReason::Budget,
                    },
                ),
            },
        };
        let pending = Pending {
            source: self.0.clone(),
            item,
            digest,
            complete,
            observed_at,
        };
        if publisher.pending.try_send(pending).is_err() {
            if self.0.active.load(Ordering::Acquire) {
                self.0.lost();
            }
            return;
        }
        // A reader may briefly own the ring; enqueue without waiting on it.
        // That reader or the next producer drains the bounded handoff.
        if let Ok(mut state) = publisher.state.try_lock() {
            state.drain_pending();
        }
        publisher.changed.notify_waiters();
    }
}
impl Source {
    fn lost(&self) {
        if self
            .loss
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .is_err()
        {
            self.broken.store(true, Ordering::Release);
        }
        if let Some(publisher) = self.publisher.upgrade() {
            publisher.changed.notify_waiters();
        }
    }
}
fn prefix(text: &str, max: usize) -> usize {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    end
}
fn append(text: &mut String, omitted: &mut u64, delta: &str) {
    let length = prefix(delta, PREVIEW_BYTES.saturating_sub(text.len()));
    text.push_str(&delta[..length]);
    *omitted = omitted.saturating_add((delta.len() - length) as u64);
}
