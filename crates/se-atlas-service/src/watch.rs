//! The native watcher thread. Windows and macOS watch the whole tree with one
//! recursive request; Linux watches each directory. Every reported path goes
//! through [`crate::filter`] before any filesystem call, so ignored and
//! private paths never cost a syscall or reach the dirty set. Lost events (a
//! queue overflow, a moved directory, a failed read) mark the dirty set
//! overflowed, which makes the writer reconcile the tree by file stats. A
//! watch that cannot be kept marks the root unwatched instead of current.
use crate::{
    dirty::Change,
    filter::{self, Reported},
    ignores::{self, Ignores},
    root::{Msg, Shared},
    settle::Watch,
};
use se_proc::{NativeSourceRoot, NativeSourceWatch, NativeWatchAction, NativeWatchEvents};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, SyncSender, sync_channel},
    },
    thread::JoinHandle,
    time::Duration,
};

const BUFFER: usize = 16 * 1024;
/// Directories one new folder may add to a per-directory watch.
#[cfg(target_os = "linux")]
const MAX_NEW_DIRECTORIES: u64 = 4096;
/// The longest the thread sleeps before it looks for events again.
#[cfg(target_os = "linux")]
const POLL: Duration = Duration::from_millis(50);
#[cfg(any(windows, target_os = "macos"))]
const POLL: Duration = Duration::from_millis(250);

pub(crate) struct Watcher {
    stop: Arc<AtomicBool>,
    wake: SyncSender<()>,
    thread: Option<JoinHandle<()>>,
}

impl Watcher {
    /// Arm the watch and start its thread. `directories` lists the tree's
    /// directories for platforms that watch each one.
    pub fn arm(shared: &Arc<Shared>, directories: &[String]) -> Result<(Self, u64), String> {
        let root = NativeSourceRoot::open(&shared.spec.source).map_err(|e| e.to_string())?;
        let watch = NativeSourceWatch::new().map_err(|e| e.to_string())?;
        let (names, watched) = subscribe(&watch, &root, directories)?;
        let stop = Arc::new(AtomicBool::new(false));
        let (wake, woken) = sync_channel(1);
        signal(&watch, &wake)?;
        let thread = std::thread::Builder::new()
            .name("atlas-watch".into())
            .spawn({
                let (shared, stop) = (shared.clone(), stop.clone());
                move || {
                    let mut state = Thread {
                        shared: &shared,
                        watch,
                        root,
                        names,
                        ignores: Ignores::default(),
                    };
                    state.run(&stop, &woken);
                }
            })
            .map_err(|e| e.to_string())?;
        Ok((
            Self {
                stop,
                wake,
                thread: Some(thread),
            },
            watched,
        ))
    }

    /// Stop the thread at once, without waiting out its poll interval.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = self.wake.try_send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Windows and macOS signal queued events; Linux is polled.
#[cfg(any(windows, target_os = "macos"))]
fn signal(watch: &NativeSourceWatch, wake: &SyncSender<()>) -> Result<(), String> {
    let wake = wake.clone();
    watch
        .set_signal(Arc::new(move || {
            let _ = wake.try_send(());
        }))
        .map_err(|e| e.to_string())
}

#[cfg(target_os = "linux")]
fn signal(_: &NativeSourceWatch, _: &SyncSender<()>) -> Result<(), String> {
    Ok(())
}

/// Descriptor to root-relative directory, for watches that report leaf names.
type Names = HashMap<u32, String>;

#[cfg(any(windows, target_os = "macos"))]
fn subscribe(
    watch: &NativeSourceWatch,
    root: &NativeSourceRoot,
    _: &[String],
) -> Result<(Names, u64), String> {
    match watch.subscribe_tree(root) {
        Ok(Some(_)) => Ok((Names::new(), 1)),
        Ok(None) => Err("the project folder disappeared".into()),
        Err(error) => Err(error.to_string()),
    }
}

/// Git's head files, including every branch folder (`feat/x` lives in
/// `refs/heads/feat`), then each source directory.
#[cfg(target_os = "linux")]
fn subscribe(
    watch: &NativeSourceWatch,
    root: &NativeSourceRoot,
    directories: &[String],
) -> Result<(Names, u64), String> {
    let mut names = Names::new();
    let mut git = vec![".git".to_owned(), ".git/refs/heads".to_owned()];
    let mut branches = vec![".git/refs/heads".to_owned()];
    while let Some(directory) = branches.pop() {
        let found = subdirectories(root, &directory).unwrap_or_default();
        git.extend(found.iter().cloned());
        branches.extend(found);
    }
    // Git metadata is optional enrichment; a failed watch there only loses
    // head tracking.
    for directory in &git {
        if let Ok(Some(registration)) = watch.subscribe(root, directory) {
            names.insert(registration.descriptor, directory.clone());
        }
    }
    for directory in std::iter::once("").chain(directories.iter().map(String::as_str)) {
        match watch.subscribe(root, directory) {
            Ok(Some(registration)) => {
                names.insert(registration.descriptor, directory.to_owned());
            }
            // A vanished directory means the tree changed, which the
            // reconcile after arming catches.
            Ok(None) => {}
            Err(error) => return Err(format!("watching {directory:?}: {error}")),
        }
    }
    let watched = names.len() as u64;
    Ok((names, watched))
}

/// Child directories of `directory`, listed through custody without
/// following links; ones the filter drops are left out.
#[cfg(target_os = "linux")]
fn subdirectories(root: &NativeSourceRoot, directory: &str) -> std::io::Result<Vec<String>> {
    let Some(mut cursor) = root.open_directory(directory)? else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    loop {
        let batch = cursor.next_batch()?;
        if batch.is_empty() {
            return Ok(out);
        }
        for entry in batch {
            if entry.kind != se_proc::NativeSourceKind::Directory {
                continue;
            }
            let Some(name) = entry.name.to_str() else {
                continue;
            };
            let child = if directory.is_empty() {
                name.to_owned()
            } else {
                format!("{directory}/{name}")
            };
            if filter::classify_directory(&child) != Reported::Drop {
                out.push(child);
            }
        }
    }
}

struct Thread<'a> {
    shared: &'a Arc<Shared>,
    watch: NativeSourceWatch,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    root: NativeSourceRoot,
    names: Names,
    /// Discovery's ignore rules, so an ignored new folder costs no watch.
    ignores: Ignores,
}

impl Thread<'_> {
    fn run(&mut self, stop: &AtomicBool, woken: &Receiver<()>) {
        let mut buffer = vec![0u8; BUFFER];
        while !stop.load(Ordering::Acquire) {
            let _ = woken.recv_timeout(POLL);
            if stop.load(Ordering::Acquire) {
                break;
            }
            loop {
                match self.watch.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => self.events(&buffer[..read]),
                    Err(error) => {
                        self.fail(&error.to_string());
                        return;
                    }
                }
            }
        }
        #[cfg(windows)]
        let _ = self.watch.shutdown(Duration::from_secs(1));
    }

    fn events(&mut self, bytes: &[u8]) {
        let mut marked = false;
        for event in NativeWatchEvents::new(bytes) {
            let Ok(event) = event else {
                self.lose();
                continue;
            };
            match event.action {
                NativeWatchAction::Overflow => {
                    self.lose();
                    continue;
                }
                NativeWatchAction::Invalidated if event.name.is_empty() => {
                    if self.root_lost(event.descriptor) {
                        self.fail("the project folder was moved, replaced or removed");
                    } else {
                        self.lose();
                    }
                    continue;
                }
                _ => {}
            }
            let Some(name) = event.name.to_str() else {
                self.lose();
                continue;
            };
            let Some(path) = self.path(event.descriptor, name) else {
                self.lose();
                continue;
            };
            marked |= self.event(event.action, event.directory, &path);
        }
        if marked {
            self.shared.send(Msg::Wake);
        }
    }

    /// Handle one named event. True when a path was marked dirty.
    fn event(&mut self, action: NativeWatchAction, flagged: bool, path: &str) -> bool {
        // The filter runs first: an ignored path never costs a syscall.
        let as_file = filter::classify(path);
        let as_directory = filter::classify_directory(path);
        if as_file == Reported::Drop && as_directory == Reported::Drop {
            return false;
        }
        if ignores::is_rule_file(path) {
            self.ignores.clear();
        }
        // Windows reports every name as a directory; the custody check
        // below tells them apart.
        let flagged = !cfg!(windows) && flagged;
        let gone = matches!(
            action,
            NativeWatchAction::Removed | NativeWatchAction::MovedFrom
        );
        if gone && !flagged {
            // The name cannot be looked at any more. A removed directory
            // whose name a private file could not hold (`secrets/`) is still
            // removed: the writer drops every indexed file below it.
            if as_file == Reported::Head || as_directory == Reported::Head {
                self.shared.send(Msg::Head);
                return false;
            }
            return self.mark(path, Change::Removed);
        }
        if flagged || (!gone && self.is_directory(path)) {
            self.directory(action, path, as_directory);
            return false;
        }
        match as_file {
            Reported::Drop => false,
            Reported::Head => {
                self.shared.send(Msg::Head);
                false
            }
            Reported::Source => self.mark(path, Change::Modified),
        }
    }

    fn mark(&self, path: &str, change: Change) -> bool {
        if let Ok(mut dirty) = self.shared.dirty() {
            dirty.mark(path, change);
        }
        true
    }

    /// The root-relative path of a name. Tree watches report it from the
    /// root; a per-directory watch whose directory is no longer known (it
    /// moved) has no trustworthy path, and its event is not attributed.
    fn path(&self, descriptor: Option<u32>, name: &str) -> Option<String> {
        let name = name.replace('\\', "/");
        match descriptor.and_then(|id| self.names.get(&id)) {
            Some(directory) if !directory.is_empty() => Some(format!("{directory}/{name}")),
            Some(_) => Some(name),
            None if cfg!(target_os = "linux") => None,
            None => Some(name),
        }
    }

    /// A directory came, went or moved: its files are unknown until a
    /// reconcile. A new branch folder only needs watching.
    #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
    fn directory(&mut self, action: NativeWatchAction, path: &str, class: Reported) {
        if class == Reported::Drop || self.ignored(path) {
            return;
        }
        match action {
            #[cfg(any(windows, target_os = "macos"))]
            NativeWatchAction::Changed => {}
            #[cfg(target_os = "linux")]
            NativeWatchAction::Changed | NativeWatchAction::MovedTo => {
                self.watch_new(path);
                if class == Reported::Head {
                    self.shared.send(Msg::Head);
                } else {
                    self.lose();
                }
            }
            #[cfg(target_os = "linux")]
            NativeWatchAction::MovedFrom | NativeWatchAction::Removed => {
                self.unwatch(path);
                self.lose();
            }
            _ if class == Reported::Head => {
                self.shared.send(Msg::Head);
            }
            _ => self.lose(),
        }
    }

    /// Whether discovery skips a source directory by its ignore rules. Git's
    /// folders are judged by the built-in filter alone.
    fn ignored(&mut self, path: &str) -> bool {
        let Some(source) = self.shared.source() else {
            return false;
        };
        filter::classify_directory(path) == Reported::Source
            && self.ignores.ignored_directory(source, path)
    }

    /// Notifications on Linux and macOS carry the directory bit.
    #[cfg(not(windows))]
    fn is_directory(&self, _: &str) -> bool {
        false
    }

    /// Windows notifications carry no directory bit, so a name that still
    /// exists is opened as a directory through custody, which refuses links
    /// and junctions rather than following them.
    #[cfg(windows)]
    fn is_directory(&self, path: &str) -> bool {
        matches!(self.root.open_directory(path), Ok(Some(_)))
    }

    /// Whether an emptied watch was the project folder's own. The tree
    /// watches have one descriptor; Linux also drops a watch whenever a
    /// subdirectory goes, which only loses that directory's events.
    #[cfg(any(windows, target_os = "macos"))]
    fn root_lost(&mut self, _: Option<u32>) -> bool {
        true
    }

    #[cfg(target_os = "linux")]
    fn root_lost(&mut self, descriptor: Option<u32>) -> bool {
        let Some(descriptor) = descriptor else {
            return true;
        };
        match self.names.get(&descriptor).map(String::is_empty) {
            Some(true) => true,
            Some(false) => {
                // A moved directory keeps its kernel watch; drop it so its
                // later events are not reported under a stale name.
                self.names.remove(&descriptor);
                let _ = self.watch.remove(descriptor);
                self.count();
                false
            }
            // Its removal was already seen.
            None => false,
        }
    }

    /// Stop watching a directory that moved away and everything below it,
    /// so a later event is never attributed to its old name.
    #[cfg(target_os = "linux")]
    fn unwatch(&mut self, path: &str) {
        let below = format!("{path}/");
        let moved: Vec<u32> = self
            .names
            .iter()
            .filter(|(_, name)| name.as_str() == path || name.starts_with(&below))
            .map(|(descriptor, _)| *descriptor)
            .collect();
        for descriptor in moved {
            self.names.remove(&descriptor);
            let _ = self.watch.remove(descriptor);
        }
        self.count();
    }

    /// Watch a new directory and every directory already inside it, so a
    /// folder moved or unpacked into the tree is watched as deep as it goes.
    /// Names are listed and subscribed through custody.
    #[cfg(target_os = "linux")]
    fn watch_new(&mut self, path: &str) {
        let mut pending = vec![path.to_owned()];
        let mut added = 0u64;
        while let Some(directory) = pending.pop() {
            if added >= MAX_NEW_DIRECTORIES {
                self.fail("too many new directories appeared at once to watch each one");
                return;
            }
            if self.ignored(&directory) {
                continue;
            }
            match self.watch.subscribe(&self.root, &directory) {
                Ok(Some(registration)) => {
                    self.names
                        .insert(registration.descriptor, directory.clone());
                    added += 1;
                }
                // Gone again before it could be watched.
                Ok(None) => continue,
                // Watched under an older name: a reconcile settles the tree.
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    self.lose();
                    continue;
                }
                Err(error) => {
                    self.fail(&format!("watching {directory:?}: {error}"));
                    return;
                }
            }
            match subdirectories(&self.root, &directory) {
                Ok(children) => pending.extend(children),
                Err(_) => self.lose(),
            }
        }
        self.count();
    }

    /// Publish how many directories are watched now.
    #[cfg(target_os = "linux")]
    fn count(&self) {
        if let Ok(mut progress) = self.shared.progress()
            && let Watch::Armed { directories } = &mut progress.watch
        {
            *directories = self.names.len() as u64;
        }
    }

    fn lose(&self) {
        if let Ok(mut dirty) = self.shared.dirty() {
            dirty.lose();
        }
        self.shared.send(Msg::Wake);
    }

    fn fail(&self, reason: &str) {
        if let Ok(mut progress) = self.shared.progress() {
            progress.watch = Watch::Failed(reason.to_owned());
        }
        self.lose();
    }
}
