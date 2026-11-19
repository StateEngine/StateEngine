//! Fresh repository facts, with one working-tree scan in flight per worktree.
//! The answer deadline does not cancel a blocking library call. Its thread owns
//! the reservation until it finishes, including after its receiver times out.
#[path = "git2.rs"]
mod backend;
#[cfg(windows)]
mod watch_inventory;
#[cfg(windows)]
mod watch_windows;
use std::{
    collections::HashSet,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock, mpsc},
    time::Instant,
};
#[cfg(windows)]
pub use watch_windows::{RepositoryWatch, WatchedFacts, watch_ticket};

/// Check whether the local caller shares the watch owner's Git environment.
#[cfg(windows)]
pub fn watch_environment() -> Result<(), String> {
    backend::watch_environment().map(|_| ())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Facts {
    pub head: Option<String>,
    pub branch: Option<String>,
    pub dirty: Option<bool>,
}

pub enum Read {
    Known(Facts),
    Fallback(String),
}

static SCANS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

struct Flight(PathBuf);
impl Flight {
    fn reserve(key: PathBuf) -> Result<Self, String> {
        let mut scans = SCANS
            .get_or_init(Mutex::default)
            .lock()
            .map_err(|_| "repository scan reservations are unreadable".to_owned())?;
        if !scans.insert(key.clone()) {
            return Err("a previous working-tree scan is still running".to_owned());
        }
        Ok(Self(key))
    }
}
impl Drop for Flight {
    fn drop(&mut self) {
        if let Some(scans) = SCANS.get()
            && let Ok(mut scans) = scans.lock()
        {
            scans.remove(&self.0);
        }
    }
}

pub fn observe(root: &Path, deadline: Instant) -> Read {
    match read(root, deadline) {
        Ok(facts) => Read::Known(facts),
        Err(reason) => Read::Fallback(reason),
    }
}

fn read(root: &Path, deadline: Instant) -> Result<Facts, String> {
    // Reopen metadata/configuration on every call. No cached dirtiness or
    // repository handle can conceal a global configuration change.
    let prepared = backend::Prepared::open(root)?;
    let facts = prepared.facts().clone();
    if facts.head.is_none() || Instant::now() >= deadline {
        return Ok(facts);
    }
    scan(facts, prepared.key().to_owned(), deadline, move || {
        prepared.scan()
    })
}

fn scan(
    mut facts: Facts,
    key: PathBuf,
    deadline: Instant,
    work: impl FnOnce() -> Result<bool, String> + Send + 'static,
) -> Result<Facts, String> {
    let flight = Flight::reserve(key)?;
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("repository-status".into())
        .spawn(move || {
            let _flight = flight;
            let result = work();
            // A caller that timed out has dropped its receiver. Completion
            // still releases this flight; it never publishes an old snapshot.
            let _ = sender.send(result);
        })
        .map_err(|error| format!("cannot start working-tree scan: {error}"))?;
    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
        return Ok(facts);
    };
    match receiver.recv_timeout(remaining) {
        Ok(result) if Instant::now() < deadline => facts.dirty = Some(result?),
        Ok(_) => {}
        Err(mpsc::RecvTimeoutError::Timeout) => {}
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            return Err("working-tree scan ended without a result".into());
        }
    }
    Ok(facts)
}
