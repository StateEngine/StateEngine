//! The single writer of one root. It opens the store, arms the watcher,
//! builds or reconciles, then commits watcher batches: changes are coalesced
//! for [`DEBOUNCE`] after the last event (at most [`MAX_DEBOUNCE`] after the
//! first) and written path by path, with lazy delta compaction when due.
use crate::{
    dirty::Change,
    filter, githead, reconcile, records,
    root::{FeedReceipt, Msg, Shared},
    settle::{Phase, Watch},
    watch::Watcher,
};
use se_atlas_index::{
    IndexError,
    custody::IndexSourceRoot,
    extract::imports::Resolver,
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
        Ok(()) => {
            let failed = shared
                .progress()
                .map_or(true, |p| matches!(p.phase, Phase::Failed(_)));
            if !failed {
                set_phase(shared, Phase::Ready);
            }
            engine.serve(receiver);
        }
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
    failed: BTreeSet<String>,
    watcher: Option<Watcher>,
    head: Option<Vec<u8>>,
    last_write: Instant,
    last_reconcile: Instant,
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
            failed: BTreeSet::new(),
            watcher: None,
            head: None,
            last_write: Instant::now(),
            last_reconcile: Instant::now(),
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
        Ok(())
    }

    /// Directories to watch where each needs its own watch.
    fn directories(&self) -> se_atlas_index::Result<Vec<String>> {
        if !cfg!(target_os = "linux") {
            return Ok(Vec::new());
        }
        let discovery = walk::discover(&self.source, &walk_options())?;
        let mut out = BTreeSet::new();
        for path in &discovery.files {
            let mut dir = path.as_str();
            while let Some(at) = dir.rfind('/') {
                dir = &dir[..at];
                if !out.insert(dir.to_owned()) {
                    break;
                }
            }
        }
        Ok(out.into_iter().collect())
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

    fn cold(&mut self) -> se_atlas_index::Result<()> {
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
        if let Ok(mut progress) = self.shared.progress() {
            progress.discovery_complete = report.discovery_complete;
            progress.counts.discovered = report.discovered as u64;
            progress.counts.unlisted_directories =
                u64::from(report.unreadable_dirs) + u64::from(report.refused_dirs);
        }
        self.last_write = Instant::now();
        if report.read_failed > 0 {
            // Name the files that failed, so each is retried when it changes.
            self.reconcile()?;
        }
        Ok(())
    }

    fn indexed_resolver(&self) -> se_atlas_index::Result<Resolver> {
        let mut select = self.store.connection().prepare("SELECT path FROM files")?;
        let paths: Vec<String> = select
            .query_map([], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(Resolver::new(paths.iter().map(String::as_str)))
    }

    /// Re-index what changed since the store was last written.
    fn reconcile(&mut self) -> se_atlas_index::Result<()> {
        self.last_reconcile = Instant::now();
        let discovery = walk::discover(&self.source, &walk_options())?;
        let changed = reconcile::changed(&self.store, &self.source, &discovery.files)?;
        if changed.len() > 2_000.max(discovery.files.len() / 2) {
            return self.cold();
        }
        self.resolver = Resolver::new(discovery.files.iter().map(String::as_str));
        if let Ok(mut progress) = self.shared.progress() {
            progress.discovery_complete = discovery.complete;
            progress.counts.discovered = discovery.files.len() as u64;
            progress.counts.unlisted_directories =
                u64::from(discovery.unreadable_dirs) + u64::from(discovery.refused_dirs);
        }
        for path in &changed {
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

    fn serve(&mut self, receiver: &Receiver<Msg>) {
        loop {
            let pending = self.shared.dirty().is_ok_and(|dirty| !dirty.is_empty());
            let wait = if pending { DEBOUNCE } else { IDLE_TICK };
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
        let unwatched = self
            .shared
            .progress()
            .is_ok_and(|p| !matches!(p.watch, Watch::Armed { .. }));
        if unwatched && self.last_reconcile.elapsed() >= UNWATCHED_RECONCILE {
            if let Ok(directories) = self.directories() {
                self.arm(&directories);
            }
            if let Ok(mut dirty) = self.shared.dirty() {
                dirty.lose();
            }
            self.flush();
        } else if pending {
            self.flush();
        } else {
            self.compact();
        }
    }

    /// Commit every dirty path; reconcile first when changes were lost.
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
        if overflowed {
            match self.reconcile() {
                Ok(()) => {
                    if let Ok(mut dirty) = self.shared.dirty() {
                        dirty.end_reconcile(token);
                    }
                }
                Err(error) => set_phase(self.shared, Phase::Failed(error.to_string())),
            }
        }
        for path in &paths {
            if path.change == Change::Removed {
                match reconcile::under(&self.store, &path.path) {
                    Ok(children) => children.iter().for_each(|child| self.index(child)),
                    // Unknown children: the next pass reconciles the tree.
                    Err(_) => {
                        if let Ok(mut dirty) = self.shared.dirty() {
                            dirty.lose();
                        }
                    }
                }
            }
            self.index(&path.path);
        }
        if let Ok(mut dirty) = self.shared.dirty() {
            for path in &paths {
                dirty.settle(&path.path, path.serial);
            }
        }
        self.compact();
        self.refresh();
    }

    fn compact(&mut self) {
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
        let indexed: Option<i64> = conn
            .query_row("SELECT count(*) FROM files", [], |row| row.get(0))
            .ok();
        let generation: Option<i64> = conn
            .query_row("SELECT generation FROM meta WHERE singleton=1", [], |row| {
                row.get(0)
            })
            .ok();
        if let Ok(mut progress) = self.shared.progress() {
            progress.batch_running = false;
            progress.counts.failed = self.failed.len() as u64;
            if let Some(indexed) = indexed {
                progress.counts.indexed = u64::try_from(indexed).unwrap_or(0);
            }
            progress.generation = generation.and_then(|g| u64::try_from(g).ok());
        }
    }

    fn record_head(&mut self) {
        let Some(oid) = githead::head(&self.shared.spec.source) else {
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
    let reader = shared.reader()?;
    let cursor = records::cursor(reader.connection());
    shared.give_back(reader);
    cursor
}
