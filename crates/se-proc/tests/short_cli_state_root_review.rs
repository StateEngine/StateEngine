//! A short CLI state root may skip the ancestor walk only briefly, and never
//! skips the root's own identity and protection checks.
#![cfg(unix)]
use se_proc::{NativeStateFiles, StateFileError, StateFileErrorCode};
use std::{
    error::Error,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Home(PathBuf);
impl Home {
    fn new() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "se-test-shortcli-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        mode(&path, 0o700)?;
        let root = path.join("state");
        fs::create_dir(&root)?;
        mode(&root, 0o700)?;
        let file = root.join("endpoint.json");
        fs::write(&file, b"{}")?;
        mode(&file, 0o600)?;
        Ok(Self(path))
    }
    fn root(&self) -> PathBuf {
        self.0.join("state")
    }
    fn file(&self) -> PathBuf {
        self.root().join("endpoint.json")
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = mode(&self.0, 0o700);
        let _ = mode(&self.root(), 0o700);
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("fixture cleanup {}: {error}", self.0.display());
        }
    }
}
fn mode(path: &Path, bits: u32) -> Check {
    fs::set_permissions(path, fs::Permissions::from_mode(bits))?;
    Ok(())
}
fn refused(
    result: Result<Option<fs::File>, StateFileError>,
) -> Result<StateFileErrorCode, Box<dyn Error>> {
    match result {
        Ok(_) => Err("short CLI readback was accepted".into()),
        Err(error) => Ok(error.code),
    }
}

#[test]
fn a_replaced_root_is_refused_inside_the_short_window() -> Check {
    let home = Home::new()?;
    let files = NativeStateFiles::open_retained(&home.root())?;
    require(files.readback(&home.file())?.is_some(), "first readback")?;
    fs::rename(home.root(), home.0.join("moved"))?;
    fs::create_dir(home.root())?;
    mode(&home.root(), 0o700)?;
    fs::write(home.file(), b"{}")?;
    mode(&home.file(), 0o600)?;
    let code = refused(files.readback(&home.file()))?;
    require(
        code == StateFileErrorCode::SourceChanged,
        "replacement code",
    )
}

#[test]
fn a_loosened_root_is_refused_inside_the_short_window() -> Check {
    let home = Home::new()?;
    let files = NativeStateFiles::open_retained(&home.root())?;
    require(files.readback(&home.file())?.is_some(), "first readback")?;
    mode(&home.root(), 0o755)?;
    refused(files.readback(&home.file()))?;
    Ok(())
}

#[test]
fn an_unsafe_ancestor_is_refused_once_the_short_window_ends() -> Check {
    let home = Home::new()?;
    let files = NativeStateFiles::open_retained(&home.root())?;
    require(files.readback(&home.file())?.is_some(), "first readback")?;
    // A non-sticky world-writable ancestor lets another user swap the root.
    mode(&home.0, 0o777)?;
    std::thread::sleep(Duration::from_millis(1_200));
    let code = refused(files.readback(&home.file()))?;
    require(code == StateFileErrorCode::LocationUnsafe, "ancestor code")?;
    // The full walk refuses the same ancestor for an ordinary open.
    let full = NativeStateFiles::open(&home.root());
    require(full.is_err(), "full walk accepted the unsafe ancestor")
}

#[test]
fn a_refreshed_parent_still_expires_and_refuses_a_later_unsafe_ancestor() -> Check {
    let home = Home::new()?;
    let files = NativeStateFiles::open_retained(&home.root())?;
    // The first expiry walks the full ancestry and retains a new parent.
    std::thread::sleep(Duration::from_millis(1_200));
    require(
        files.readback(&home.file())?.is_some(),
        "refreshing readback",
    )?;
    mode(&home.0, 0o777)?;
    // Steady use must not keep the parent fresh: within a few windows of the
    // change, some access walks the full ancestry and refuses.
    let deadline = std::time::Instant::now() + Duration::from_millis(2_500);
    while std::time::Instant::now() < deadline {
        if let Err(error) = files.readback(&home.file()) {
            return require(
                error.code == StateFileErrorCode::LocationUnsafe,
                "ancestor code",
            );
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    Err("the retained parent never expired under steady use".into())
}

fn require(ok: bool, what: &str) -> Check {
    if ok { Ok(()) } else { Err(what.into()) }
}
