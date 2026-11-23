//! The native watcher thread. Windows and macOS watch the whole tree with one
//! recursive request; Linux watches each directory. Every reported path goes
//! through [`crate::filter`] first, so ignored and private paths never reach
//! the dirty set. Lost events (a queue overflow, a removed directory, a
//! failed read) mark the dirty set overflowed, which makes the writer
//! reconcile the tree by file stats.
use crate::{
    dirty::Change,
    filter::{self, Reported},
    root::{Msg, Shared},
    settle::Watch,
};
use se_proc::{NativeSourceRoot, NativeSourceWatch, NativeWatchAction, NativeWatchEvents};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::JoinHandle,
    time::Duration,
};

const BUFFER: usize = 16 * 1024;
/// Directories one new folder may add to a per-directory watch.
#[cfg(target_os = "linux")]
const MAX_NEW_DIRECTORIES: u64 = 4096;

pub(crate) struct Watcher {
    stop: Arc<AtomicBool>,
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
        let wake = signal(&watch)?;
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
                    };
                    state.run(&stop, &wake);
                }
            })
            .map_err(|e| e.to_string())?;
        Ok((
            Self {
                stop,
                thread: Some(thread),
            },
            watched,
        ))
    }

    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// How the thread learns that events are queued.
#[cfg(any(windows, target_os = "macos"))]
type Wake = std::sync::mpsc::Receiver<()>;
#[cfg(target_os = "linux")]
type Wake = ();

#[cfg(any(windows, target_os = "macos"))]
fn signal(watch: &NativeSourceWatch) -> Result<Wake, String> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    watch
        .set_signal(Arc::new(move || {
            let _ = sender.try_send(());
        }))
        .map_err(|e| e.to_string())?;
    Ok(receiver)
}

#[cfg(target_os = "linux")]
fn signal(_: &NativeSourceWatch) -> Result<Wake, String> {
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

#[cfg(target_os = "linux")]
fn subscribe(
    watch: &NativeSourceWatch,
    root: &NativeSourceRoot,
    directories: &[String],
) -> Result<(Names, u64), String> {
    let mut names = Names::new();
    for directory in std::iter::once("")
        .chain([".git", ".git/refs/heads"])
        .chain(directories.iter().map(String::as_str))
    {
        match watch.subscribe(root, directory) {
            Ok(Some(registration)) => {
                names.insert(registration.descriptor, directory.to_owned());
            }
            // Git metadata is optional; a missing source directory means the
            // tree changed, which the reconcile after arming catches.
            Ok(None) => {}
            Err(_) if directory.starts_with(".git") => {}
            Err(error) => return Err(format!("watching {directory:?}: {error}")),
        }
    }
    let watched = names.len() as u64;
    Ok((names, watched))
}

struct Thread<'a> {
    shared: &'a Arc<Shared>,
    watch: NativeSourceWatch,
    #[cfg_attr(any(windows, target_os = "macos"), allow(dead_code))]
    root: NativeSourceRoot,
    names: Names,
}

impl Thread<'_> {
    fn run(&mut self, stop: &AtomicBool, wake: &Wake) {
        let mut buffer = vec![0u8; BUFFER];
        while !stop.load(Ordering::Acquire) {
            wait(wake);
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
            let path = self.path(event.descriptor, name);
            if self.is_directory(event.directory, event.action, &path) {
                self.directory(event.action, &path);
                continue;
            }
            match filter::classify(&path) {
                Reported::Drop => {}
                Reported::Head => {
                    self.shared.send(Msg::Head);
                }
                Reported::Source => {
                    let change = match event.action {
                        NativeWatchAction::Removed | NativeWatchAction::MovedFrom => {
                            Change::Removed
                        }
                        _ => Change::Modified,
                    };
                    if let Ok(mut dirty) = self.shared.dirty() {
                        dirty.mark(&path, change);
                    }
                    marked = true;
                }
            }
        }
        if marked {
            self.shared.send(Msg::Wake);
        }
    }

    fn path(&self, descriptor: Option<u32>, name: &str) -> String {
        let name = name.replace('\\', "/");
        match descriptor.and_then(|id| self.names.get(&id)) {
            Some(directory) if !directory.is_empty() => format!("{directory}/{name}"),
            _ => name,
        }
    }

    /// A directory came or went: its files are unknown until a reconcile.
    fn directory(&mut self, action: NativeWatchAction, path: &str) {
        if filter::classify(&format!("{path}/x")) == Reported::Drop {
            return;
        }
        match action {
            #[cfg(any(windows, target_os = "macos"))]
            NativeWatchAction::Changed => {}
            #[cfg(target_os = "linux")]
            NativeWatchAction::Changed | NativeWatchAction::MovedTo => {
                self.watch_new(path);
                self.lose();
            }
            _ => self.lose(),
        }
    }

    #[cfg(not(windows))]
    fn is_directory(&self, flagged: bool, _: NativeWatchAction, _: &str) -> bool {
        flagged
    }

    /// Windows notifications carry no directory bit, so a name that still
    /// exists is looked at without following links. A removed name is taken
    /// as a file; the writer also drops indexed files below it.
    #[cfg(windows)]
    fn is_directory(&self, _: bool, action: NativeWatchAction, path: &str) -> bool {
        match action {
            NativeWatchAction::Changed | NativeWatchAction::MovedTo => {
                std::fs::symlink_metadata(self.shared.spec.source.join(path))
                    .is_ok_and(|meta| meta.is_dir())
            }
            _ => false,
        }
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
                self.names.remove(&descriptor);
                false
            }
            // Its removal was already seen.
            None => false,
        }
    }

    /// Watch a new directory and every directory already inside it, so a
    /// folder moved or unpacked into the tree is watched as deep as it goes.
    /// Names are only listed here; each subscription is custody-checked.
    #[cfg(target_os = "linux")]
    fn watch_new(&mut self, path: &str) {
        let mut pending = vec![path.to_owned()];
        let mut added = 0u64;
        while let Some(directory) = pending.pop() {
            if added >= MAX_NEW_DIRECTORIES {
                self.fail("too many new directories appeared at once to watch each one");
                return;
            }
            let Ok(Some(registration)) = self.watch.subscribe(&self.root, &directory) else {
                continue;
            };
            self.names
                .insert(registration.descriptor, directory.clone());
            added += 1;
            let Ok(entries) = std::fs::read_dir(self.shared.spec.source.join(&directory)) else {
                continue;
            };
            for entry in entries.flatten() {
                if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                    continue;
                }
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let child = format!("{directory}/{name}");
                if filter::classify(&format!("{child}/x")) != Reported::Drop {
                    pending.push(child);
                }
            }
        }
        if let Ok(mut progress) = self.shared.progress()
            && let Watch::Armed { directories } = &mut progress.watch
        {
            *directories += added;
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

#[cfg(any(windows, target_os = "macos"))]
fn wait(wake: &Wake) {
    let _ = wake.recv_timeout(Duration::from_millis(250));
}

#[cfg(target_os = "linux")]
fn wait((): &Wake) {
    std::thread::sleep(Duration::from_millis(50));
}
