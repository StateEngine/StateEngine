//! One registered worktree: its writer thread, its watcher, and the state
//! both share with queries.
use crate::{
    dirty::DirtySet,
    error::{index_error, poisoned},
    settle::Progress,
};
use se_atlas_index::{custody::IndexSourceRoot, store::Reader};
use se_types::{
    ProjectId, Result,
    code::{CacheEpoch, IndexSummary, RecordFeed, RootId},
};
use std::{
    path::PathBuf,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender, SyncSender},
    },
    thread::JoinHandle,
    time::Duration,
};

/// Which worktree to index and where its store lives.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootSpec {
    pub project: ProjectId,
    pub root: RootId,
    /// The canonical physical source root the project registered.
    pub source: PathBuf,
    /// A directory owned by this root alone; the store lives inside it.
    pub directory: PathBuf,
}

/// What a record feed batch did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeedReceipt {
    pub changed: u32,
    pub complete: bool,
}

pub(crate) type FeedReply = SyncSender<Result<FeedReceipt>>;

pub(crate) enum Msg {
    /// The watcher marked paths dirty.
    Wake,
    /// Git moved `HEAD`.
    Head,
    Feed(Box<RecordFeed>, FeedReply),
    Stop,
}

/// Readers are pooled per store epoch; a rebuild empties the pool.
#[derive(Default)]
pub(crate) struct ReaderPool {
    epoch: Option<CacheEpoch>,
    idle: Vec<Reader>,
}

pub(crate) struct Shared {
    pub spec: RootSpec,
    pub source: OnceLock<Arc<IndexSourceRoot>>,
    pub dirty: Mutex<DirtySet>,
    pub progress: Mutex<Progress>,
    pub stopping: AtomicBool,
    readers: Mutex<ReaderPool>,
    sender: Sender<Msg>,
}

const IDLE_READERS: usize = 2;

impl Shared {
    pub fn db(&self) -> PathBuf {
        self.spec.directory.join("atlas.db")
    }

    pub fn dirty(&self) -> Result<MutexGuard<'_, DirtySet>> {
        self.dirty.lock().map_err(|_| poisoned("dirty set"))
    }

    pub fn progress(&self) -> Result<MutexGuard<'_, Progress>> {
        self.progress.lock().map_err(|_| poisoned("index progress"))
    }

    /// Wake the writer. A closed channel means it already stopped.
    pub fn send(&self, msg: Msg) -> bool {
        self.sender.send(msg).is_ok()
    }

    pub fn stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    pub fn summary(&self) -> Result<IndexSummary> {
        let progress = self.progress()?.clone();
        let dirty = self.dirty()?;
        Ok(IndexSummary {
            project: self.spec.project.clone(),
            root: self.spec.root.clone(),
            epoch: progress.epoch.clone(),
            generation: progress.generation.map(se_types::code::Generation),
            state: progress.state(&dirty),
            coverage: progress.coverage(&dirty),
            memory: None,
        })
    }

    /// A read-only connection to the current epoch, from the pool when one
    /// is idle.
    pub fn reader(&self) -> Result<Reader> {
        let epoch = self.progress()?.epoch.clone();
        {
            let mut pool = self.readers.lock().map_err(|_| poisoned("reader pool"))?;
            if pool.epoch != epoch {
                pool.idle.clear();
                pool.epoch = epoch;
            }
            if let Some(reader) = pool.idle.pop() {
                return Ok(reader);
            }
        }
        Reader::open(&self.db()).map_err(|error| index_error(&error))
    }

    pub fn give_back(&self, reader: Reader) {
        let Ok(epoch) = self.progress().map(|p| p.epoch.clone()) else {
            return;
        };
        if let Ok(mut pool) = self.readers.lock()
            && pool.epoch == epoch
            && pool.idle.len() < IDLE_READERS
        {
            pool.idle.push(reader);
        }
    }

    pub fn source(&self) -> Option<&Arc<IndexSourceRoot>> {
        self.source.get()
    }
}

/// A started root. Dropping it does not stop the writer; call [`Root::stop`].
pub struct Root {
    pub(crate) shared: Arc<Shared>,
    writer: Mutex<Option<JoinHandle<()>>>,
}

impl Root {
    /// Start the writer thread. No disk work happens on the caller's thread.
    pub fn start(spec: RootSpec) -> Result<Arc<Self>> {
        let (sender, receiver) = mpsc::channel();
        let shared = Arc::new(Shared {
            spec,
            source: OnceLock::new(),
            dirty: Mutex::new(DirtySet::default()),
            progress: Mutex::new(Progress::default()),
            stopping: AtomicBool::new(false),
            readers: Mutex::new(ReaderPool::default()),
            sender,
        });
        let writer = std::thread::Builder::new()
            .name("atlas-writer".into())
            .spawn({
                let shared = shared.clone();
                move || crate::engine::run(&shared, &receiver)
            })
            .map_err(|error| index_error(&se_atlas_index::IndexError::Io(error)))?;
        Ok(Arc::new(Self {
            shared,
            writer: Mutex::new(Some(writer)),
        }))
    }

    pub fn spec(&self) -> &RootSpec {
        &self.shared.spec
    }

    pub fn summary(&self) -> Result<IndexSummary> {
        self.shared.summary()
    }

    /// Fold one committed record feed batch into the store, through the writer.
    pub fn apply_feed(&self, feed: RecordFeed, timeout: Duration) -> Result<FeedReceipt> {
        let (reply, answer) = mpsc::sync_channel(1);
        if !self.shared.send(Msg::Feed(Box::new(feed), reply)) {
            return Err(stopped());
        }
        answer.recv_timeout(timeout).map_err(|_| {
            se_types::SeError::new(se_types::Detail::DeadlineExceeded(
                se_types::details::DeadlineExceeded {
                    op: "Atlas record feed".into(),
                    deadline_ms: u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX),
                },
            ))
        })?
    }

    /// Stop the watcher and writer, waiting up to `timeout` for the writer.
    pub fn stop(&self, timeout: Duration) -> Result<()> {
        self.shared.stopping.store(true, Ordering::Release);
        self.shared.send(Msg::Stop);
        let handle = self
            .writer
            .lock()
            .map_err(|_| poisoned("writer handle"))?
            .take();
        let Some(handle) = handle else {
            return Ok(());
        };
        let until = std::time::Instant::now() + timeout;
        while !handle.is_finished() {
            if std::time::Instant::now() >= until {
                return Err(se_types::SeError::invalid(
                    "Atlas writer shutdown",
                    "the writer to finish its batch within the shutdown bound",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        handle
            .join()
            .map_err(|_| se_types::SeError::invalid("Atlas writer", "a writer that did not panic"))
    }
}

pub(crate) fn stopped() -> se_types::SeError {
    crate::error::unavailable("the Atlas writer for this worktree has stopped")
}
