//! One bounded event queue shared by the live resource slots. All wakes derive
//! from source events, explicit activation or unfinished work; no idle timer.
use crate::{
    errors::{AtlasResult, capacity},
    lifecycle::*,
    model::*,
};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
const PATHS: usize = 64;
// Leave the rest of the 50 KB share for retained VecDeque capacity, the two
// root states and allocator headers. Overflow retains a reconciliation request.
const BYTES: usize = 32_000;
#[expect(
    clippy::struct_excessive_bools,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
struct Root {
    id: RootId,
    serial: u64,
    reconcile: Option<ReconcileReason>,
    first: Option<Instant>,
    last: Option<Instant>,
    git_lock: bool,
    suspended: bool,
    processing: bool,
    publication: bool,
    watch_pending: bool,
}
pub struct Scheduled {
    pub root: RootId,
    pub serial: u64,
    pub hint: SourceHint,
}
struct Queued {
    root: RootId,
    serial: u64,
    hint: SourceHint,
    bytes: usize,
    paths: usize,
}
/// Window in which source work must settle before a fresh publication is
/// offered. The production default stays 10 s; independent consumers shorten
/// it explicitly instead of waiting it out.
pub const DEFAULT_PUBLICATION_DELAY: Duration = Duration::from_secs(10);
pub struct Scheduler {
    roots: Vec<Root>,
    queue: VecDeque<Queued>,
    bytes: usize,
    paths: usize,
    turn: usize,
    publication_delay: Duration,
}
impl Default for Scheduler {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            queue: VecDeque::new(),
            bytes: 0,
            paths: 0,
            turn: 0,
            publication_delay: DEFAULT_PUBLICATION_DELAY,
        }
    }
}
impl Scheduler {
    /// Replace the publication window for a consumer that must not wait the
    /// production default; the scheduler logic itself is unchanged.
    pub fn with_publication_delay(mut self, delay: Duration) -> Self {
        self.publication_delay = delay;
        self
    }
    pub(crate) fn pending(&self, id: &RootId) -> bool {
        self.roots
            .iter()
            .find(|root| &root.id == id)
            .is_some_and(|root| {
                !root.suspended
                    && (root.processing
                        || root.watch_pending
                        || root.reconcile.is_some()
                        || self.queue.iter().any(|queued| &queued.root == id))
            })
    }
    pub(crate) fn serial(&self, id: &RootId) -> AtlasResult<u64> {
        self.roots
            .iter()
            .find(|root| &root.id == id)
            .map(|root| root.serial)
            .ok_or_else(|| {
                se_types::SeError::invalid("Atlas publication serial", "an admitted scheduler root")
            })
    }
    pub fn admit(&mut self, id: RootId) -> AtlasResult<()> {
        if self.roots.iter().any(|r| r.id == id) {
            return Ok(());
        }
        if self.roots.len() >= 2 {
            return Err(capacity("Atlas live work slots", 1, 0));
        }
        self.roots.push(Root {
            id,
            serial: 0,
            reconcile: None,
            first: None,
            last: None,
            git_lock: false,
            suspended: false,
            processing: false,
            publication: false,
            watch_pending: false,
        });
        Ok(())
    }
    pub fn remove(&mut self, id: &RootId) {
        self.roots.retain(|r| &r.id != id);
        self.queue.retain(|q| &q.root != id);
        self.bytes = self.queue.iter().map(|q| q.bytes).sum();
        self.paths = self.queue.iter().map(|q| q.paths).sum();
    }
    pub(crate) fn watch_pending(&self, id: &RootId) -> bool {
        self.roots
            .iter()
            .find(|root| &root.id == id)
            .is_some_and(|root| root.watch_pending)
    }
    pub(crate) fn set_watch_pending(&mut self, id: &RootId, pending: bool) -> AtlasResult<()> {
        let root = self
            .roots
            .iter_mut()
            .find(|root| &root.id == id)
            .ok_or_else(|| {
                se_types::SeError::invalid("Atlas watch", "an admitted scheduler root")
            })?;
        root.watch_pending = pending;
        Ok(())
    }
    pub fn enqueue(
        &mut self,
        id: &RootId,
        hint: SourceHint,
        now: Instant,
    ) -> AtlasResult<ScheduleReceipt> {
        // Keep compact path copies instead of retaining spare capacity in a
        // native event buffer. Byte accounting charges the cloned path lengths.
        let hint = hint.clone();
        let root =
            self.roots.iter_mut().find(|r| &r.id == id).ok_or_else(|| {
                se_types::SeError::invalid("Atlas root", "an admitted active root")
            })?;
        root.serial = root
            .serial
            .checked_add(1)
            .ok_or_else(|| capacity("Atlas source serial", 1, 0))?;
        root.first.get_or_insert(now);
        root.last = Some(now);
        root.publication = true;
        root.suspended = false;
        if let SourceHint::Reconcile(reason) = hint {
            if root.reconcile != Some(ReconcileReason::GitHeadChanged) {
                root.reconcile = Some(reason);
            }
            return Ok(ScheduleReceipt::ReconciliationRequired);
        }
        let (bytes, paths) = size(&hint);
        if let Some(queued) = self
            .queue
            .iter_mut()
            .find(|q| q.root == *id && same_path(&q.hint, &hint))
        {
            queued.hint = hint;
            queued.serial = root.serial;
            return Ok(ScheduleReceipt::Coalesced);
        }
        if self.paths + paths > PATHS || self.bytes + bytes > BYTES {
            root.reconcile.get_or_insert(ReconcileReason::WatchOverflow);
            return Ok(ScheduleReceipt::ReconciliationRequired);
        }
        self.queue.push_back(Queued {
            root: id.clone(),
            serial: root.serial,
            hint,
            bytes,
            paths,
        });
        self.bytes += bytes;
        self.paths += paths;
        Ok(ScheduleReceipt::Queued)
    }
    pub fn git_lock(&mut self, id: &RootId, held: bool, now: Instant) -> AtlasResult<()> {
        self.enqueue(
            id,
            SourceHint::Reconcile(ReconcileReason::GitHeadChanged),
            now,
        )?;
        let root = self
            .roots
            .iter_mut()
            .find(|r| &r.id == id)
            .ok_or_else(|| se_types::SeError::invalid("Atlas root", "admitted root"))?;
        root.git_lock = held;
        Ok(())
    }
    pub fn take(&mut self, now: Instant) -> Option<Scheduled> {
        for step in 0..self.roots.len() {
            let index = (self.turn + step) % self.roots.len();
            let root = &mut self.roots[index];
            if root.processing || root.suspended || !due(root, now) {
                continue;
            }
            if let Some(reason) = root.reconcile.take() {
                root.processing = true;
                self.turn = index + 1;
                // Full reconciliation covers all hints through this serial.
                self.queue.retain(|q| q.root != root.id);
                self.bytes = self.queue.iter().map(|q| q.bytes).sum();
                self.paths = self.queue.iter().map(|q| q.paths).sum();
                return Some(Scheduled {
                    root: root.id.clone(),
                    serial: root.serial,
                    hint: SourceHint::Reconcile(reason),
                });
            }
            if let Some(position) = self.queue.iter().position(|q| q.root == root.id) {
                let queued = self.queue.remove(position)?;
                self.bytes -= queued.bytes;
                self.paths -= queued.paths;
                root.processing = true;
                self.turn = index + 1;
                return Some(Scheduled {
                    root: queued.root,
                    serial: queued.serial,
                    hint: queued.hint,
                });
            }
        }
        None
    }
    /// Events received during work remain queued and must settle before Current.
    pub fn finished(&mut self, id: &RootId, _serial: u64, success: bool) {
        if let Some(root) = self.roots.iter_mut().find(|r| &r.id == id) {
            root.processing = false;
            if !success {
                root.suspended = true;
                root.reconcile.get_or_insert(ReconcileReason::WatchFailure);
            }
        }
    }
    pub fn publication_ready(&self, id: &RootId, now: Instant) -> bool {
        self.roots.iter().find(|r| &r.id == id).is_some_and(|r| {
            r.publication
                && !r.git_lock
                && !r.suspended
                && !r.watch_pending
                && !r.processing
                && r.reconcile.is_none()
                && !self.queue.iter().any(|q| q.root == r.id)
                && r.first.is_some_and(|first| {
                    now.saturating_duration_since(first) >= self.publication_delay
                })
        })
    }
    pub fn published(&mut self, id: &RootId) {
        if let Some(r) = self.roots.iter_mut().find(|r| &r.id == id) {
            r.first = None;
            r.last = None;
            r.publication = false;
        }
    }
    pub fn next_work(&self, now: Instant) -> NextWork {
        let mut delay = None;
        for root in &self.roots {
            if root.suspended {
                continue;
            }
            if root.watch_pending {
                let wait = Duration::from_secs(1);
                delay = Some(delay.map_or(wait, |old: Duration| old.min(wait)));
            }
            if root.processing {
                return NextWork::Ready;
            }
            let pending = root.reconcile.is_some() || self.queue.iter().any(|q| q.root == root.id);
            if pending && due(root, now) || self.publication_ready(&root.id, now) {
                return NextWork::Ready;
            }
            if pending {
                if let Some(last) = root.last {
                    let wait = Duration::from_millis(15)
                        .saturating_sub(now.saturating_duration_since(last));
                    delay = Some(delay.map_or(wait, |old: Duration| old.min(wait)));
                }
            } else if root.publication
                && !root.git_lock
                && !root.watch_pending
                && let Some(first) = root.first
            {
                let wait = self
                    .publication_delay
                    .saturating_sub(now.saturating_duration_since(first));
                delay = Some(delay.map_or(wait, |old: Duration| old.min(wait)));
            }
        }
        delay.map_or(NextWork::Park, NextWork::AfterEventDebounce)
    }
}
fn due(root: &Root, now: Instant) -> bool {
    root.first
        .is_some_and(|first| now.saturating_duration_since(first) >= Duration::from_secs(2))
        || root
            .last
            .is_some_and(|last| now.saturating_duration_since(last) >= Duration::from_millis(15))
}
fn size(hint: &SourceHint) -> (usize, usize) {
    use se_types::code::AtlasText;
    let overhead = std::mem::size_of::<Queued>() + 64; // bounded root-ID storage
    match hint {
        SourceHint::FileChanged(p)
        | SourceHint::FileRemoved(p)
        | SourceHint::DirectoryChanged(p) => (overhead + p.as_str().len(), 1),
        SourceHint::Rename { from, to } => (overhead + from.as_str().len() + to.as_str().len(), 2),
        SourceHint::Reconcile(_) => (overhead, 0),
    }
}
fn same_path(a: &SourceHint, b: &SourceHint) -> bool {
    match (a, b) {
        (
            SourceHint::FileChanged(a) | SourceHint::FileRemoved(a),
            SourceHint::FileChanged(b) | SourceHint::FileRemoved(b),
        ) => a == b,
        (SourceHint::DirectoryChanged(a), SourceHint::DirectoryChanged(b)) => a == b,
        _ => false,
    }
}
