//! Native watcher thread: recursive on Windows/macOS, per-directory on Linux.
//! Paths pass through [`crate::filter`] before any syscall; lost events mark
//! the dirty set overflowed so the writer reconciles by file stats.
//! Drains queued events, then blocks with no timer until signaled or stopped.
use crate::{
    dirty::Change,
    filter::{self, Reported},
    ignores::{self, Ignores},
    root::{Msg, Shared},
    settle::Watch,
};
use se_proc::{NativeSourceRoot, NativeSourceWatch, NativeWatchAction, NativeWatchEvents};
#[cfg(any(windows, target_os = "macos"))]
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
};

const BUFFER: usize = 16 * 1024;
/// Directories one new folder may add to a per-directory watch.
#[cfg(target_os = "linux")]
const MAX_NEW_DIRECTORIES: u64 = 4096;

/// What wakes the sleeping thread, and what it sleeps on. Linux blocks in
/// the inotify source itself; Windows and macOS signal a channel whenever
/// they queue an event.
#[cfg(target_os = "linux")]
type Wake = se_proc::NativeWatchWake;
#[cfg(target_os = "linux")]
type Woken = ();
#[cfg(any(windows, target_os = "macos"))]
type Wake = SyncSender<()>;
#[cfg(any(windows, target_os = "macos"))]
type Woken = Receiver<()>;

pub(crate) struct Watcher {
    stop: Arc<AtomicBool>,
    wake: Wake,
    thread: Option<JoinHandle<()>>,
}

impl Watcher {
    /// Arm the watch and start its thread. `directories` lists the tree's
    /// directories for platforms that watch each one.
    pub fn arm(shared: &Arc<Shared>, directories: &[String]) -> Result<(Self, u64), String> {
        let root = NativeSourceRoot::open(&shared.spec.source).map_err(|e| e.to_string())?;
        let watch = NativeSourceWatch::new().map_err(|e| e.to_string())?;
        let (names, watched) = subscribe(&watch, &root, &shared.spec.source, directories)?;
        let stop = Arc::new(AtomicBool::new(false));
        let (wake, woken) = signal(&watch)?;
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

    /// Stop the thread at once: it is woken, not left to find out later.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        #[cfg(target_os = "linux")]
        let _ = self.wake.wake();
        #[cfg(any(windows, target_os = "macos"))]
        let _ = self.wake.try_send(());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Windows and macOS signal each queued event on a one-slot channel.
#[cfg(any(windows, target_os = "macos"))]
fn signal(watch: &NativeSourceWatch) -> Result<(Wake, Woken), String> {
    let (wake, woken) = sync_channel(1);
    let signal = wake.clone();
    watch
        .set_signal(Arc::new(move || {
            let _ = signal.try_send(());
        }))
        .map_err(|e| e.to_string())?;
    Ok((wake, woken))
}

#[cfg(target_os = "linux")]
fn signal(watch: &NativeSourceWatch) -> Result<(Wake, Woken), String> {
    Ok((watch.wake_handle().map_err(|e| e.to_string())?, ()))
}

/// Descriptor to root-relative directory, for watches that report leaf names.
type Names = HashMap<u32, String>;

#[cfg(any(windows, target_os = "macos"))]
fn subscribe(
    watch: &NativeSourceWatch,
    root: &NativeSourceRoot,
    _: &std::path::Path,
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
    source: &std::path::Path,
    directories: &[String],
) -> Result<(Names, u64), String> {
    let needed = directories.len().saturating_add(1);
    if let Some(limit) = std::fs::read_to_string("/proc/sys/fs/inotify/max_user_watches")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
        && needed > limit
    {
        return Err(format!(
            "inotify watch limit ({limit}) is smaller than the {needed} directories in this tree; raise fs.inotify.max_user_watches or ignore large directories"
        ));
    }
    let mut names = Names::new();
    // Git metadata is optional enrichment; a failed watch there only loses head tracking.
    let linked = crate::githead::linked_roots(source);
    let (git_root, git_dir, refs_root, refs_dir, prefix) = match &linked {
        Some((git, common)) => (
            git,
            "",
            common.as_ref().unwrap_or(git),
            "refs/heads",
            ".git/",
        ),
        None => (root, ".git", root, ".git/refs/heads", ""),
    };
    if let Ok(Some(reg)) = watch.subscribe(git_root, git_dir) {
        names.insert(reg.descriptor, ".git".to_owned());
    }
    let mut branches = vec![refs_dir.to_owned()];
    while let Some(dir) = branches.pop() {
        if let Ok(Some(reg)) = watch.subscribe(refs_root, &dir) {
            names.insert(reg.descriptor, format!("{prefix}{dir}"));
        }
        branches.extend(subdirectories(refs_root, &dir).unwrap_or_default());
    }
    for directory in std::iter::once("").chain(directories.iter().map(String::as_str)) {
        match watch.subscribe(root, directory) {
            Ok(Some(registration)) => {
                names.insert(registration.descriptor, directory.to_owned());
            }
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
    /// Drain first, then sleep: an event queued after the drain signals the
    /// sleep, so none waits for a timer and an idle watch never wakes.
    fn run(&mut self, stop: &AtomicBool, woken: &Woken) {
        let mut buffer = vec![0u8; BUFFER];
        while !stop.load(Ordering::Acquire) {
            match self.watch.read(&mut buffer) {
                Ok(0) => {}
                Ok(read) => {
                    self.events(&buffer[..read]);
                    continue;
                }
                Err(error) => return self.fail(&error.to_string()),
            }
            if stop.load(Ordering::Acquire) || !self.sleep(woken) {
                break;
            }
        }
        #[cfg(windows)]
        let _ = self.watch.shutdown(std::time::Duration::from_secs(1));
    }

    /// Block until events or a stop arrive. False when the thread must end.
    #[cfg(target_os = "linux")]
    fn sleep(&mut self, _: &Woken) -> bool {
        match self.watch.wait() {
            Ok(()) => true,
            Err(error) => {
                self.fail(&error.to_string());
                false
            }
        }
    }

    /// Block until the native watch or stop signals.
    #[cfg(any(windows, target_os = "macos"))]
    fn sleep(&mut self, woken: &Woken) -> bool {
        woken.recv().is_ok()
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
        if class == Reported::Drop {
            return;
        }
        if matches!(
            action,
            NativeWatchAction::MovedTo | NativeWatchAction::MovedFrom | NativeWatchAction::Removed
        ) {
            self.ignores.clear();
        }
        if self.ignored(path) {
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

    fn lose(&mut self) {
        self.ignores.clear();
        if let Ok(mut dirty) = self.shared.dirty() {
            dirty.lose();
        }
        self.shared.send(Msg::Wake);
    }

    fn fail(&mut self, reason: &str) {
        if let Ok(mut progress) = self.shared.progress() {
            progress.watch = Watch::Failed(reason.to_owned());
        }
        self.lose();
    }
}
