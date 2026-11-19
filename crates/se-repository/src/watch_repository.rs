//! Bounded, watched Git dirtiness. A read names its last reconcile and never
//! represents notifications as a synchronous proof of the working tree.
use super::{Facts, Flight, backend::Prepared};
use se_proc::{NativeSourceRoot, NativeSourceWatch, NativeWatchAction, NativeWatchEvents};
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const RETRY_RECONCILE: Duration = Duration::from_secs(30);
const MAX_EVENTS: usize = 128;

#[derive(Clone, Debug)]
pub struct WatchedFacts {
    pub facts: Facts,
    pub commits: Option<u64>,
    pub reconciled_at_us: u64,
    pub last_notification_at_us: Option<u64>,
}

enum Command {
    Wake,
    Query {
        deadline: Instant,
        result: mpsc::SyncSender<Result<WatchedFacts, String>>,
    },
}

pub struct RepositoryWatch {
    root: PathBuf,
    commands: mpsc::SyncSender<Command>,
    stopping: Arc<AtomicBool>,
}
impl RepositoryWatch {
    pub fn start(root: &Path) -> Result<Self, String> {
        let root = root.to_path_buf();
        let (commands, receiver) = mpsc::sync_channel(1);
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_stopping = stopping.clone();
        let worker_commands = commands.clone();
        let worker_root = root.clone();
        thread::Builder::new()
            .name("repository-watch".into())
            .spawn(move || {
                Worker::new(worker_root, worker_commands, receiver, worker_stopping).run();
            })
            .map_err(|error| format!("cannot start repository watcher: {error}"))?;
        Ok(Self {
            root,
            commands,
            stopping,
        })
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn observe(&self, deadline: Instant) -> Result<WatchedFacts, String> {
        let (result, receiver) = mpsc::sync_channel(1);
        self.commands
            .try_send(Command::Query { deadline, result })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => "watched repository is reconciling".to_owned(),
                mpsc::TrySendError::Disconnected(_) => {
                    "watched repository worker stopped".to_owned()
                }
            })?;
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .ok_or("watched repository deadline elapsed")?;
        receiver
            .recv_timeout(timeout)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => {
                    "watched repository did not settle before its deadline".to_owned()
                }
                mpsc::RecvTimeoutError::Disconnected => {
                    "watched repository worker stopped without a result".to_owned()
                }
            })?
    }
}
impl Drop for RepositoryWatch {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        let _ = self.commands.try_send(Command::Wake);
    }
}

struct Armed {
    source: NativeSourceRoot,
    git: NativeSourceRoot,
    common: Option<NativeSourceRoot>,
    watch: NativeSourceWatch,
    source_descriptor: u32,
    git_descriptor: u32,
    common_descriptor: Option<u32>,
    prepared: Prepared,
    commits: Option<u64>,
    changed: HashSet<String>,
    changed_bytes: usize,
    revision: u64,
    reconciled_at_us: u64,
    ticket: String,
}
impl Armed {
    fn update(&mut self, key: String, changed: bool) -> Result<(), String> {
        if changed && !self.changed.contains(&key) {
            let bytes = self.changed_bytes.saturating_add(key.len());
            if self.changed.len() >= 32768 || bytes > 4_000_000 {
                return Err("working-tree change set exceeds its bound".into());
            }
            self.changed_bytes = bytes;
            self.changed.insert(key);
        } else if !changed && self.changed.remove(&key) {
            self.changed_bytes = self.changed_bytes.saturating_sub(key.len());
        }
        Ok(())
    }
}
struct Worker {
    root: PathBuf,
    sender: mpsc::SyncSender<Command>,
    commands: mpsc::Receiver<Command>,
    serial: Arc<AtomicU64>,
    notification: Arc<AtomicU64>,
    armed: Option<Armed>,
    next_reconcile: Instant,
    error: String,
    stopping: Arc<AtomicBool>,
}
impl Worker {
    fn new(
        root: PathBuf,
        sender: mpsc::SyncSender<Command>,
        commands: mpsc::Receiver<Command>,
        stopping: Arc<AtomicBool>,
    ) -> Self {
        Self {
            root,
            sender,
            commands,
            serial: Arc::new(AtomicU64::new(0)),
            notification: Arc::new(AtomicU64::new(0)),
            armed: None,
            next_reconcile: Instant::now(),
            error: "watch initialization is pending".into(),
            stopping,
        }
    }
    fn run(mut self) {
        self.reconcile();
        loop {
            if self.stopping.load(Ordering::Acquire) {
                break;
            }
            match self.commands.recv() {
                Err(_) => break,
                Ok(Command::Wake) => {
                    if self.armed.is_none() {
                        if Instant::now() >= self.next_reconcile {
                            self.reconcile();
                        }
                    } else if let Err(error) = self.changes() {
                        self.error = error;
                        self.armed = None;
                        self.reconcile();
                    }
                }
                Ok(Command::Query { deadline, result }) => {
                    let value = self.query(deadline);
                    let needs_reconcile =
                        self.armed.is_none() && Instant::now() >= self.next_reconcile;
                    let _ = result.send(value);
                    if needs_reconcile {
                        self.reconcile();
                    }
                }
            }
        }
    }
    fn reconcile(&mut self) {
        self.armed = None;
        let result = self.arm();
        self.next_reconcile = Instant::now() + RETRY_RECONCILE;
        match result {
            Ok(armed) => self.armed = Some(armed),
            Err(error) => self.error = error,
        }
    }
    fn arm(&self) -> Result<Armed, String> {
        let prepared = Prepared::open(&self.root)?;
        prepared.watchable()?;
        let source = NativeSourceRoot::open(prepared.key()).map_err(|e| e.to_string())?;
        let git =
            NativeSourceRoot::open(prepared.metadata_directory()).map_err(|e| e.to_string())?;
        let common = if prepared.common_directory() == prepared.metadata_directory() {
            None
        } else {
            Some(NativeSourceRoot::open(prepared.common_directory()).map_err(|e| e.to_string())?)
        };
        let watch = NativeSourceWatch::new().map_err(|e| e.to_string())?;
        let serial = self.serial.clone();
        let notification = self.notification.clone();
        let sender = self.sender.clone();
        watch
            .set_signal(Arc::new(move || {
                serial.fetch_add(1, Ordering::AcqRel);
                notification.store(now_us().unwrap_or(u64::MAX), Ordering::Release);
                let _ = sender.try_send(Command::Wake);
            }))
            .map_err(|e| e.to_string())?;
        let source_descriptor = watch
            .subscribe_tree(&source)
            .map_err(|e| format!("working-tree watch could not start: {e}"))?
            .ok_or("working-tree watch disappeared while arming")?
            .descriptor;
        let git_descriptor = watch
            .subscribe_tree(&git)
            .map_err(|e| format!("Git metadata watch could not start: {e}"))?
            .ok_or("Git metadata watch disappeared while arming")?
            .descriptor;
        let common_descriptor = common
            .as_ref()
            .map(|root| {
                watch
                    .subscribe_tree(root)
                    .map_err(|e| format!("Git common-directory watch could not start: {e}"))?
                    .ok_or_else(|| "Git common-directory watch disappeared while arming".to_owned())
                    .map(|registration| registration.descriptor)
            })
            .transpose()?;
        let before = self.serial.load(Ordering::Acquire);
        let _flight = Flight::reserve(prepared.key().to_owned())?;
        let changed = prepared.inventory()?;
        let commits = prepared.commit_count();
        let reconciled_at_us = now_us().ok_or("system clock unavailable")?;
        watch
            .synchronize(Duration::from_millis(100))
            .map_err(|e| e.to_string())?;
        let mut buffer = [0; 16384];
        if watch.read(&mut buffer).map_err(|e| e.to_string())? != 0
            || self.serial.load(Ordering::Acquire) != before
        {
            return Err("working tree changed during watch reconciliation".into());
        }
        let ticket = prepared.ticket()?;
        let current = Prepared::open(&self.root)?;
        current.watchable()?;
        if current.ticket()? != ticket {
            return Err("repository configuration changed during reconciliation".into());
        }
        if self.serial.load(Ordering::Acquire) != before {
            return Err("working tree changed during watch reconciliation".into());
        }
        let changed_bytes = changed.iter().map(String::len).sum();
        Ok(Armed {
            source,
            git,
            common,
            watch,
            source_descriptor,
            git_descriptor,
            common_descriptor,
            prepared,
            commits,
            changed,
            changed_bytes,
            revision: before,
            reconciled_at_us,
            ticket,
        })
    }
    fn changes(&mut self) -> Result<(), String> {
        let armed = self.armed.as_mut().ok_or_else(|| self.error.clone())?;
        let start = self.serial.load(Ordering::Acquire);
        armed
            .watch
            .synchronize(Duration::from_millis(100))
            .map_err(|e| e.to_string())?;
        let mut buffer = [0; 16384];
        let mut processed = 0usize;
        let mut current = None;
        loop {
            let count = armed.watch.read(&mut buffer).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            for event in NativeWatchEvents::new(&buffer[..count]) {
                let event = event.map_err(|e| e.to_string())?;
                processed += 1;
                if processed > MAX_EVENTS {
                    return Err("watch event burst requires reconciliation".into());
                }
                if matches!(
                    event.action,
                    NativeWatchAction::Overflow | NativeWatchAction::Invalidated
                ) {
                    return Err("watch coverage was lost; fresh reconciliation required".into());
                }
                if event.descriptor == Some(armed.git_descriptor)
                    || event.descriptor.is_some() && event.descriptor == armed.common_descriptor
                {
                    return Err("Git metadata changed; fresh reconciliation required".into());
                }
                if event.descriptor != Some(armed.source_descriptor) {
                    return Err("unrecognized source watch; fresh reconciliation required".into());
                }
                let path = event.name.to_str().ok_or("watch path is not UTF-8")?;
                let key = eligible_path(armed.prepared.key(), path)?;
                if current.is_none() {
                    let observed = Prepared::open(&self.root)?;
                    observed.watchable()?;
                    if observed.ticket()? != armed.ticket {
                        return Err(
                            "repository configuration changed; reconciliation required".into()
                        );
                    }
                    current = Some(observed);
                }
                let changed = current
                    .as_ref()
                    .ok_or("repository observation unavailable")?
                    .changed_file(Path::new(path))?;
                armed.update(key, changed)?;
            }
        }
        if self.serial.load(Ordering::Acquire) != start {
            return Err("working tree changed during watch update".into());
        }
        if current.is_some() {
            let observed = Prepared::open(&self.root)?;
            observed.watchable()?;
            if observed.ticket()? != armed.ticket {
                return Err("repository configuration changed during watch update".into());
            }
        }
        armed.revision = start;
        Ok(())
    }
    fn query(&mut self, deadline: Instant) -> Result<WatchedFacts, String> {
        if Instant::now() >= deadline {
            return Err("watched repository deadline elapsed".into());
        }
        if self.armed.is_none() {
            return Err(self.error.clone());
        }
        if let Err(error) = self.changes() {
            self.error = error.clone();
            self.armed = None;
            self.next_reconcile = Instant::now();
            return Err(error);
        }
        let identity = (|| {
            let armed = self.armed.as_ref().ok_or("watch unavailable")?;
            armed.source.check().map_err(|e| e.to_string())?;
            armed.git.check().map_err(|e| e.to_string())?;
            if let Some(common) = &armed.common {
                common.check().map_err(|e| e.to_string())?;
            }
            let current = Prepared::open(&self.root)?;
            current.watchable()?;
            let ticket = current.ticket()?;
            Ok::<_, String>((current, ticket))
        })();
        let (current, ticket) = match identity {
            Ok(value) => value,
            Err(error) => {
                self.error = error.clone();
                self.armed = None;
                self.next_reconcile = Instant::now();
                return Err(error);
            }
        };
        let armed = self.armed.as_ref().ok_or("watch unavailable")?;
        if ticket != armed.ticket || current.facts() != armed.prepared.facts() {
            self.armed = None;
            self.next_reconcile = Instant::now();
            return Err("repository configuration or HEAD changed; reconciliation required".into());
        }
        if self.serial.load(Ordering::Acquire) != armed.revision {
            return Err("source change is still being observed".into());
        }
        let mut facts = current.facts().clone();
        facts.dirty = facts.head.as_ref().map(|_| !armed.changed.is_empty());
        let last_notification_at_us = match self.notification.load(Ordering::Acquire) {
            0 => None,
            u64::MAX => return Err("source notification time is unavailable".into()),
            value => Some(value),
        };
        Ok(WatchedFacts {
            facts,
            commits: armed.commits,
            reconciled_at_us: armed.reconciled_at_us,
            last_notification_at_us,
        })
    }
}
fn eligible_path(root: &Path, path: &str) -> Result<String, String> {
    if !path.is_ascii() {
        return Err("non-ASCII watch paths require reconciliation".into());
    }
    #[cfg(target_os = "macos")]
    if path.contains('\\') {
        return Err("ambiguous watch path requires reconciliation".into());
    }
    if path.split('/').any(|part| {
        part.eq_ignore_ascii_case(".git")
            || part.eq_ignore_ascii_case(".gitignore")
            || part.eq_ignore_ascii_case(".gitattributes")
            || part.eq_ignore_ascii_case(".gitmodules")
    }) {
        return Err("Git rules changed; fresh reconciliation required".into());
    }
    let native_path = root.join(path);
    let metadata = std::fs::symlink_metadata(&native_path)
        .map_err(|_| "removed or inaccessible path requires reconciliation")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || is_reparse(&metadata) {
        return Err("directory or linked-path change requires reconciliation".into());
    }
    let resolved = native_path
        .canonicalize()
        .map_err(|_| "cannot resolve changed path")?;
    let relative = resolved
        .strip_prefix(root)
        .map_err(|_| "changed path escaped its retained root")?;
    let spelling = relative
        .to_str()
        .ok_or("changed path is not UTF-8")?
        .replace('\\', "/");
    if !spelling.eq_ignore_ascii_case(path) {
        return Err("aliased changed path requires reconciliation".into());
    }
    Ok(path.to_ascii_lowercase())
}

#[cfg(windows)]
fn is_reparse(metadata: &std::fs::Metadata) -> bool {
    metadata.file_attributes() & 0x400 != 0
}
#[cfg(target_os = "macos")]
fn is_reparse(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn now_us() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|n| u64::try_from(n.as_micros()).ok())
}
