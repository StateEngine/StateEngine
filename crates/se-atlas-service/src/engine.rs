//! The single writer of one root. It opens the store, arms the watcher,
//! builds or reconciles, then commits watcher batches: changes are coalesced
//! for [`DEBOUNCE`] after the last event (at most [`MAX_DEBOUNCE`] after the
//! first) and written path by path, with lazy delta compaction when due.
//! Every long loop checks for a stop between files, so shutdown is prompt.
use crate::{
    dirty::{Change, DirtyPath},
    filter, githead,
    ignores::{self, Ignores},
    reconcile, records,
    root::{FeedReceipt, Msg, Shared},
    settle::{Phase, Watch},
    watch::Watcher,
};
use se_atlas_index::{
    IndexError,
    custody::IndexSourceRoot,
    extract::{flags, imports::Resolver},
    store::{BuildOptions, CompactPolicy, Store, StoreIdentity},
    walk::{self, WalkOptions},
};
use se_types::code::CacheEpoch;
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        mpsc::{Receiver, RecvTimeoutError},
    },
    time::{Duration, Instant},
};

/// Quiet time that ends a burst.
pub const DEBOUNCE: Duration = Duration::from_millis(75);
/// The longest a burst is held before it is written anyway.
pub const MAX_DEBOUNCE: Duration = Duration::from_millis(500);
/// How often an idle writer checks compaction and a failed watch.
const IDLE_TICK: Duration = Duration::from_secs(2);
/// How often a writer without a working watch re-arms and reconciles.
const UNWATCHED_RECONCILE: Duration = Duration::from_secs(30);
/// How often files that could not be read are tried again.
const RETRY_FAILED: Duration = Duration::from_secs(10);
/// The longest a head change waits for Git to release its index lock.
const HEAD_LOCK_WAIT: Duration = Duration::from_secs(2);

type Outcome<T> = std::result::Result<T, String>;

pub(crate) fn run(shared: &Arc<Shared>, receiver: &Receiver<Msg>) {
    let mut engine = match Engine::open(shared) {
        Ok(engine) => engine,
        Err(reason) => {
            set_phase(shared, Phase::Failed(reason));
            refuse_feeds(receiver);
            return;
        }
    };
    match engine.prepare() {
        Err(reason) => set_phase(shared, Phase::Failed(reason)),
        Ok(()) => engine.serve(receiver),
    }
    if let Some(watcher) = engine.watcher.take() {
        watcher.stop();
    }
    set_phase(shared, Phase::Stopped);
}

fn set_phase(shared: &Shared, phase: Phase) {
    if let Ok(mut progress) = shared.progress() {
        progress.phase = phase;
    }
}

/// End a build or reconcile: the root is ready unless it failed meanwhile.
fn settle_phase(shared: &Shared) {
    if let Ok(mut progress) = shared.progress()
        && !matches!(progress.phase, Phase::Failed(_) | Phase::Stopped)
    {
        progress.phase = Phase::Ready;
    }
}

/// A writer that failed to open still answers feed requests, with a refusal.
fn refuse_feeds(receiver: &Receiver<Msg>) {
    while let Ok(msg) = receiver.recv() {
        match msg {
            Msg::Stop => return,
            Msg::Feed(_, reply) => {
                let _ = reply.send(Err(crate::root::stopped()));
            }
            Msg::Wake | Msg::Head => {}
        }
    }
}

pub(crate) fn walk_options() -> WalkOptions {
    WalkOptions {
        global_patterns: filter::global_patterns(),
        ..WalkOptions::default()
    }
}

struct Engine<'a> {
    shared: &'a Arc<Shared>,
    store: Store,
    source: Arc<IndexSourceRoot>,
    resolver: Resolver,
    ignores: Ignores,
    /// Files that could not be read, by name; retried every [`RETRY_FAILED`].
    failed: BTreeSet<String>,
    /// Files a build could not read, before a reconcile names them.
    unnamed_failed: u64,
    watcher: Option<Watcher>,
    head: Option<Vec<u8>>,
    /// When a head change began waiting for Git's index lock.
    head_waiting: Option<Instant>,
    last_write: Instant,
    last_reconcile: Instant,
    last_retry: Instant,
    jobs: u64,
    rebuild: bool,
}

impl<'a> Engine<'a> {
    fn open(shared: &'a Arc<Shared>) -> Outcome<Self> {
        let spec = &shared.spec;
        std::fs::create_dir_all(&spec.directory)
            .map_err(|e| format!("cannot create the index folder: {e}"))?;
        let source = Arc::new(
            IndexSourceRoot::open(&spec.source)
                .map_err(|e| format!("cannot open the project folder: {e}"))?,
        );
        let display = spec.source.display().to_string();
        let identity = StoreIdentity {
            project: spec.project.as_str().to_owned(),
            root: display.clone(),
            physical_root: display,
        };
        let (store, rebuild) = Store::open(&shared.db(), &identity)
            .map_err(|e| format!("cannot open atlas.db: {e}"))?;
        let _ = shared.source.set(source.clone());
        let mut engine = Self {
            shared,
            store,
            source,
            resolver: Resolver::new(std::iter::empty::<&str>()),
            ignores: Ignores::default(),
            failed: BTreeSet::new(),
            unnamed_failed: 0,
            watcher: None,
            head: None,
            head_waiting: None,
            last_write: Instant::now(),
            last_reconcile: Instant::now(),
            last_retry: Instant::now(),
            jobs: 0,
            rebuild: rebuild.is_some(),
        };
        engine.publish_epoch().map_err(|e| e.to_string())?;
        Ok(engine)
    }

    /// The store epoch as the wire names it, stable for the store's life.
    fn publish_epoch(&mut self) -> se_atlas_index::Result<()> {
        let created: i64 = self.store.connection().query_row(
            "SELECT epoch FROM meta WHERE singleton=1",
            [],
            |row| row.get(0),
        )?;
        let mut seed = blake3::Hasher::new();
        seed.update(self.shared.spec.root.as_str().as_bytes());
        seed.update(&created.to_le_bytes());
        let mut entropy = [0u8; 10];
        entropy.copy_from_slice(&seed.finalize().as_bytes()[..10]);
        let millis = u64::try_from(created).unwrap_or(0).min(0xffff_ffff_ffff);
        let epoch = CacheEpoch::from_parts(millis, entropy)
            .map_err(|_| IndexError::Corrupt("store epoch"))?;
        if let Ok(mut progress) = self.shared.progress() {
            progress.epoch = Some(epoch);
        }
        Ok(())
    }

    fn prepare(&mut self) -> Outcome<()> {
        let discovery_complete: i64 = self
            .store
            .connection()
            .query_row(
                "SELECT discovery_complete FROM meta WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .map_err(|e| e.to_string())?;
        // Arm before building, so edits made during the build are not lost.
        let directories = self.directories().map_err(|e| e.to_string())?;
        self.arm(&directories);
        if self.rebuild || discovery_complete == 0 {
            self.cold().map_err(|e| e.to_string())?;
        } else {
            set_phase(self.shared, Phase::Reconciling);
            self.reconcile().map_err(|e| e.to_string())?;
        }
        self.record_head();
        self.refresh();
        settle_phase(self.shared);
        Ok(())
    }

    /// Every directory discovery enters, empty ones included, where each
    /// needs its own watch.
    fn directories(&self) -> se_atlas_index::Result<Vec<String>> {
        if !cfg!(target_os = "linux") {
            return Ok(Vec::new());
        }
        Ok(walk::discover(&self.source, &walk_options())?.directories)
    }

    fn arm(&mut self, directories: &[String]) {
        if let Some(watcher) = self.watcher.take() {
            watcher.stop();
        }
        let watch = match Watcher::arm(self.shared, directories) {
            Ok((watcher, directories)) => {
                self.watcher = Some(watcher);
                Watch::Armed { directories }
            }
            Err(reason) => Watch::Failed(reason),
        };
        if let Ok(mut progress) = self.shared.progress() {
            progress.watch = watch;
        }
    }

    /// Rebuild the store. Files the build could not read are counted, and a
    /// reconcile soon after names each one; the build never recurses into it.
    fn cold(&mut self) -> se_atlas_index::Result<()> {
        if self.shared.stopping() {
            return Ok(());
        }
        self.jobs += 1;
        set_phase(
            self.shared,
            Phase::Cold {
                job: self.jobs,
                discovered: 0,
            },
        );
        let report = self.store.cold_build(
            &self.source,
            &BuildOptions {
                walk: walk_options(),
                ..BuildOptions::default()
            },
        )?;
        self.resolver = self.indexed_resolver()?;
        self.failed.clear();
        self.unnamed_failed = report.read_failed as u64;
        if report.read_failed > 0 {
            // Due at once: the next idle tick reconciles and names them.
            self.last_retry = Instant::now()
                .checked_sub(RETRY_FAILED)
                .unwrap_or(self.last_retry);
        }
        if let Ok(mut progress) = self.shared.progress() {
            progress.discovery_complete = report.discovery_complete;
            progress.counts.discovered = report.discovered as u64;
            progress.counts.unlisted_directories =
                u64::from(report.unreadable_dirs) + u64::from(report.refused_dirs);
        }
        self.last_write = Instant::now();
        self.refresh();
        settle_phase(self.shared);
        Ok(())
    }

    fn indexed_resolver(&self) -> se_atlas_index::Result<Resolver> {
        let mut select = self.store.connection().prepare("SELECT path FROM files")?;
        let paths: Vec<String> = select
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(Resolver::new(paths.iter().map(String::as_str)))
    }

    /// Re-index what changed since the store was last written, and remove
    /// what discovery no longer lists (deleted, newly ignored or denied).
    fn reconcile(&mut self) -> se_atlas_index::Result<()> {
        if self.shared.stopping() {
            return Ok(());
        }
        self.last_reconcile = Instant::now();
        let discovery = walk::discover(&self.source, &walk_options())?;
        let delta = reconcile::changed(&self.store, &self.source, &discovery.files)?;
        if delta.changed.len() + delta.gone.len() > 2_000.max(discovery.files.len() / 2) {
            return self.cold();
        }
        self.resolver = Resolver::new(discovery.files.iter().map(String::as_str));
        if let Ok(mut progress) = self.shared.progress() {
            progress.discovery_complete = discovery.complete;
            progress.counts.discovered = discovery.files.len() as u64;
            progress.counts.unlisted_directories =
                u64::from(discovery.unreadable_dirs) + u64::from(discovery.refused_dirs);
        }
        self.unnamed_failed = 0;
        self.failed
            .retain(|path| discovery.files.binary_search(path).is_ok());
        self.failed.extend(delta.failed);
        for path in &delta.gone {
            if self.shared.stopping() {
                return Ok(());
            }
            self.forget(path);
        }
        for path in &delta.changed {
            if self.shared.stopping() {
                return Ok(());
            }
            self.index(path);
        }
        Ok(())
    }

    /// Index one path, retrying once a file that changed while it was read.
    fn index(&mut self, path: &str) {
        self.last_write = Instant::now();
        for _ in 0..2 {
            if self
                .store
                .index_path(&self.source, &mut self.resolver, path)
                .is_ok()
            {
                self.failed.remove(path);
                return;
            }
        }
        if self.source.check().is_err() {
            set_phase(
                self.shared,
                Phase::Failed("the project folder was moved, replaced or removed".into()),
            );
        }
        self.failed.insert(path.to_owned());
    }

    /// Drop one path's rows; it is no longer discovered.
    fn forget(&mut self, path: &str) {
        self.last_write = Instant::now();
        self.resolver.remove(path);
        if self.store.remove_file(path).is_err() {
            self.failed.insert(path.to_owned());
        } else {
            self.failed.remove(path);
        }
    }

    fn serve(&mut self, receiver: &Receiver<Msg>) {
        loop {
            let pending = self.shared.dirty().is_ok_and(|dirty| !dirty.is_empty());
            let wait = if pending || self.head_waiting.is_some() {
                DEBOUNCE
            } else {
                IDLE_TICK
            };
            match receiver.recv_timeout(wait) {
                Ok(Msg::Stop) | Err(RecvTimeoutError::Disconnected) => return,
                Ok(Msg::Wake) => {
                    if self.debounce(receiver) {
                        return;
                    }
                    self.flush();
                }
                Ok(Msg::Head) => self.record_head(),
                Ok(Msg::Feed(feed, reply)) => {
                    let _ = reply.send(self.feed(&feed));
                }
                Err(RecvTimeoutError::Timeout) => self.idle(pending),
            }
            if self.shared.stopping() {
                return;
            }
        }
    }

    /// Absorb a burst. True when a stop arrived.
    fn debounce(&mut self, receiver: &Receiver<Msg>) -> bool {
        let started = Instant::now();
        loop {
            let left = MAX_DEBOUNCE.saturating_sub(started.elapsed());
            if left.is_zero() {
                return false;
            }
            match receiver.recv_timeout(DEBOUNCE.min(left)) {
                Ok(Msg::Wake) => {}
                Ok(Msg::Head) => self.record_head(),
                Ok(Msg::Feed(feed, reply)) => {
                    let _ = reply.send(self.feed(&feed));
                }
                Ok(Msg::Stop) | Err(RecvTimeoutError::Disconnected) => return true,
                Err(RecvTimeoutError::Timeout) => return false,
            }
        }
    }

    fn idle(&mut self, pending: bool) {
        if self.head_waiting.is_some() {
            self.record_head();
        }
        let unwatched = self
            .shared
            .progress()
            .is_ok_and(|p| !matches!(p.watch, Watch::Armed { .. }));
        let retry = (!self.failed.is_empty() || self.unnamed_failed > 0)
            && self.last_retry.elapsed() >= RETRY_FAILED;
        if unwatched && self.last_reconcile.elapsed() >= UNWATCHED_RECONCILE {
            if let Ok(directories) = self.directories() {
                self.arm(&directories);
            }
            self.lose();
            self.flush();
        } else if retry {
            self.retry();
        } else if pending {
            self.flush();
        } else {
            self.compact();
        }
    }

    /// Try unreadable files again, so a transient lock (an antivirus scan,
    /// a sharing violation) recovers to current without an edit.
    fn retry(&mut self) {
        self.last_retry = Instant::now();
        if self.unnamed_failed > 0 {
            self.lose();
            self.flush();
            return;
        }
        let failed: Vec<String> = self.failed.iter().cloned().collect();
        for path in &failed {
            if self.shared.stopping() {
                return;
            }
            self.index(path);
        }
        self.refresh();
    }

    fn lose(&self) {
        if let Ok(mut dirty) = self.shared.dirty() {
            dirty.lose();
        }
    }

    /// Commit every dirty path; reconcile first when changes were lost or an
    /// ignore rule file changed.
    fn flush(&mut self) {
        let Ok((paths, overflowed, token)) = self.shared.dirty().map(|dirty| {
            (
                dirty.snapshot(),
                dirty.overflowed(),
                dirty.begin_reconcile(),
            )
        }) else {
            return;
        };
        if let Ok(mut progress) = self.shared.progress() {
            progress.batch_running = true;
        }
        let rules = paths.iter().any(|dirty| ignores::is_rule_file(&dirty.path));
        if rules {
            self.ignores.clear();
        }
        if overflowed || rules {
            match self.reconcile() {
                Ok(()) if overflowed => {
                    if let Ok(mut dirty) = self.shared.dirty() {
                        dirty.end_reconcile(token);
                    }
                }
                Ok(()) => {}
                Err(error) => set_phase(self.shared, Phase::Failed(error.to_string())),
            }
        }
        let mut done = Vec::with_capacity(paths.len());
        for path in &paths {
            if self.shared.stopping() {
                break;
            }
            self.commit(path);
            done.push(path);
        }
        if let Ok(mut dirty) = self.shared.dirty() {
            for path in done {
                dirty.settle(&path.path, path.serial);
            }
        }
        self.compact();
        self.refresh();
    }

    /// Write one dirty path. A path the ignore rules exclude is removed, not
    /// read; a removed name also drops every indexed file below it.
    fn commit(&mut self, path: &DirtyPath) {
        if path.change == Change::Removed {
            match reconcile::under(&self.store, &path.path) {
                Ok(children) => children.iter().for_each(|child| self.index(child)),
                // Unknown children: the next pass reconciles the tree.
                Err(_) => self.lose(),
            }
        } else if self.ignores.ignored(&self.source, &path.path) {
            self.forget(&path.path);
            return;
        }
        self.index(&path.path);
    }

    fn compact(&mut self) {
        if self.shared.stopping() {
            return;
        }
        let policy = CompactPolicy::default();
        if self
            .store
            .compaction_due(&policy, self.last_write.elapsed())
            .unwrap_or(false)
        {
            let _ = self.store.compact_deltas(&policy, false);
        }
    }

    /// Publish file counts and the generation after a write.
    fn refresh(&self) {
        let conn = self.store.connection();
        let count = |sql: &str| -> Option<u64> {
            conn.query_row(sql, [], |row| row.get::<_, i64>(0))
                .ok()
                .and_then(|n| u64::try_from(n).ok())
        };
        let indexed = count("SELECT count(*) FROM files");
        let generation = count("SELECT generation FROM meta WHERE singleton=1");
        let extract_failed = conn
            .query_row(
                "SELECT count(*) FROM files WHERE flags & ?1 != 0",
                [i64::from(flags::EXTRACT_FAILED)],
                |row| row.get::<_, i64>(0),
            )
            .ok()
            .and_then(|n| u64::try_from(n).ok());
        if let Ok(mut progress) = self.shared.progress() {
            progress.batch_running = false;
            progress.counts.failed = self.failed.len() as u64 + self.unnamed_failed;
            if let Some(indexed) = indexed {
                progress.counts.indexed = indexed;
            }
            // Unreadable counts are not zero: keep the last known value.
            if let Some(extract_failed) = extract_failed {
                progress.counts.extract_failed = extract_failed;
            }
            progress.generation = generation;
        }
    }

    /// Record the commit `HEAD` names, once Git has let go of its index lock
    /// or [`HEAD_LOCK_WAIT`] has passed.
    fn record_head(&mut self) {
        let source = &self.shared.spec.source;
        if githead::busy(source) {
            let since = *self.head_waiting.get_or_insert_with(Instant::now);
            if since.elapsed() < HEAD_LOCK_WAIT {
                return;
            }
        }
        self.head_waiting = None;
        let Some(oid) = githead::head(source) else {
            return;
        };
        if self.head.as_ref() == Some(&oid) {
            return;
        }
        if self.store.record_commit(&oid).is_ok() {
            self.head = Some(oid);
            self.refresh();
        }
    }

    fn feed(&mut self, feed: &se_types::code::RecordFeed) -> se_types::Result<FeedReceipt> {
        records::apply(self.store.connection(), &self.shared.spec.project, feed)
    }
}

/// The store's record cursor, read through a query connection.
pub(crate) fn feed_cursor(shared: &Shared) -> se_types::Result<Option<se_types::EventId>> {
    shared.with_reader(|reader| records::cursor(reader.connection()))
}
