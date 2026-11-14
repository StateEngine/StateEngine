use se_proc::{NativeStateFiles, StateFileErrorCode};
use std::{
    error::Error,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Home(PathBuf);
impl Home {
    fn new() -> Result<Self, Box<dyn Error>> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path = std::env::temp_dir().join(format!(
            "se-test-statefiles-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        let home = Self(path);
        protect(&home.0)?;
        Ok(home)
    }
    fn root(&self) -> PathBuf {
        self.0.join("state")
    }
    // Independent fixture setup permits read-path cases even when native create fails.
    fn existing(&self) -> Result<NativeStateFiles, Box<dyn Error>> {
        fs::create_dir(self.root())?;
        protect(&self.root())?;
        Ok(NativeStateFiles::open(&self.root())?)
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("fixture cleanup {}: {error}", self.0.display());
        }
    }
}

#[cfg(unix)]
fn protect(path: &Path) -> Check {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if path.is_dir() { 0o700 } else { 0o600 }),
    )?;
    Ok(())
}
#[cfg(unix)]
fn observe_protection(path: &Path) -> Check {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let meta = fs::symlink_metadata(path)?;
    assert!(!meta.file_type().is_symlink());
    assert_eq!(
        meta.permissions().mode() & 0o777,
        if meta.is_dir() { 0o700 } else { 0o600 }
    );
    assert_eq!(
        meta.uid(),
        fs::metadata(path.parent().ok_or("parent")?)?.uid()
    );
    Ok(())
}

#[cfg(windows)]
#[path = "support/state_files_acl.rs"]
mod state_files_acl;
#[cfg(windows)]
use state_files_acl::acl;

#[cfg(windows)]
fn protect(path: &Path) -> Check {
    acl(path, "protect")
}
#[cfg(windows)]
fn observe_protection(path: &Path) -> Check {
    acl(path, "observe")
}

fn read(mut file: fs::File) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Protects: G8 — real staging publishes protected bytes and is independently read back.
#[test]
fn protected_staging_publishes_and_reads_back() -> Check {
    let home = Home::new()?;
    let files = NativeStateFiles::create(&home.root())?;
    observe_protection(&home.root())?;
    assert!(files.readback(&home.root().join("missing"))?.is_none());
    let mut stage = files.create_staging(&home.root())?;
    stage.file.write_all(b"a committed database image")?;
    observe_protection(&stage.path)?;
    drop(stage.file);
    let target = home.root().join("state.db");
    files.publish_no_replace(&stage.path, &target)?;
    assert_eq!(fs::read(&target)?, b"a committed database image");
    assert_eq!(
        read(files.readback(&target)?.ok_or("published image absent")?)?,
        fs::read(&target)?
    );
    assert!(!stage.path.try_exists()?);
    observe_protection(&target)?;
    Ok(())
}

/// The original writable handle survives name retirement on Windows and Unix.
#[test]
fn empty_staging_is_anonymous_before_text_and_closes_without_a_residue() -> Check {
    use std::io::{Seek, SeekFrom};
    let home = Home::new()?;
    let files = NativeStateFiles::create(&home.root())?;
    let stage = files.create_staging(&home.root())?;
    let path = stage.path.clone();
    let mut file = files.retire_empty_staging(stage)?;
    assert!(
        files.readback(&path)?.is_none(),
        "staging remained named before text"
    );
    file.write_all(b"private staged text")?;
    file.seek(SeekFrom::Start(0))?;
    assert_eq!(read(file)?, b"private staged text");
    assert_eq!(fs::read_dir(home.root())?.count(), 0);
    Ok(())
}

#[test]
fn anonymous_staging_refuses_nonempty_files_without_removing_their_names() -> Check {
    let home = Home::new()?;
    let files = NativeStateFiles::create(&home.root())?;
    let mut stage = files.create_staging(&home.root())?;
    stage.file.write_all(b"preserve")?;
    let path = stage.path.clone();
    assert!(files.retire_empty_staging(stage).is_err());
    assert_eq!(fs::read(path)?, b"preserve");
    Ok(())
}

/// Protects: G8 — colliding publishers preserve exactly one winner and the losing bytes.
#[test]
fn concurrent_publication_preserves_the_winner_and_loser() -> Check {
    let home = Home::new()?;
    let files = Arc::new(home.existing()?);
    let mut paths = Vec::new();
    for body in [b"first".as_slice(), b"second".as_slice()] {
        let mut stage = files.create_staging(&home.root())?;
        stage.file.write_all(body)?;
        drop(stage.file);
        paths.push(stage.path);
    }
    let target = home.root().join("state.db");
    let start = Arc::new(Barrier::new(2));
    let jobs: Vec<_> = paths
        .iter()
        .map(|path| {
            let (path, target, files, start) =
                (path.clone(), target.clone(), files.clone(), start.clone());
            std::thread::spawn(move || {
                start.wait();
                files.publish_no_replace(&path, &target)
            })
        })
        .collect();
    let results: Vec<_> = jobs
        .into_iter()
        .map(|j| j.join().map_err(|_| "publisher panicked"))
        .collect::<Result<_, _>>()?;
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    for (index, result) in results.into_iter().enumerate() {
        let expected = [b"first".as_slice(), b"second".as_slice()][index];
        match result {
            Ok(()) => {
                assert_eq!(fs::read(&target)?, expected);
                assert!(!paths[index].try_exists()?);
            }
            Err(error) => {
                assert_eq!(error.code, StateFileErrorCode::AlreadyExists);
                assert_eq!(fs::read(&paths[index])?, expected);
            }
        }
    }
    observe_protection(&target)?;
    Ok(())
}

/// Protects: G4/G8 — missing is distinct from unsafe protection, links and non-files.
#[test]
fn readback_refuses_unsafe_objects_without_fabricating_absence() -> Check {
    let home = Home::new()?;
    let files = home.existing()?;
    assert!(files.readback(&home.root().join("absent"))?.is_none());
    assert_eq!(
        files
            .readback(&home.0.join("outside"))
            .err()
            .ok_or("outside admitted")?
            .code,
        StateFileErrorCode::LocationUnsafe
    );
    let path = home.root().join("state.db");
    fs::write(&path, b"preserved")?;
    protect(&path)?;
    assert_eq!(
        read(files.readback(&path)?.ok_or("safe image absent")?)?,
        b"preserved"
    );
    let link = home.root().join("second-name");
    fs::hard_link(&path, &link)?;
    assert_eq!(
        files
            .readback(&path)
            .err()
            .ok_or("hard-linked image admitted")?
            .code,
        StateFileErrorCode::LocationUnsafe
    );
    fs::remove_file(&link)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    }
    #[cfg(windows)]
    acl(&path, "loosen")?;
    assert_eq!(
        files
            .readback(&path)
            .err()
            .ok_or("public image admitted")?
            .code,
        StateFileErrorCode::LocationUnsafe
    );
    assert_eq!(fs::read(&path)?, b"preserved");
    let directory = home.root().join("not-a-file");
    fs::create_dir(&directory)?;
    protect(&directory)?;
    assert!(files.readback(&directory).is_err());
    #[cfg(unix)]
    {
        protect(&path)?;
        let symlink = home.root().join("link");
        std::os::unix::fs::symlink(&path, &symlink)?;
        assert!(files.readback(&symlink).is_err());
        let directory_link = home.root().join("directory-link");
        std::os::unix::fs::symlink(&directory, &directory_link)?;
        assert!(files.readback(&directory_link.join("absent")).is_err());
        assert_eq!(fs::read(&path)?, b"preserved");
    }
    Ok(())
}

/// Protects: G8 — pinned root replacement cannot redirect an admitted file read.
#[test]
fn held_root_keeps_its_native_identity() -> Check {
    let home = Home::new()?;
    let files = home.existing()?;
    let moved = home.0.join("original");
    #[cfg(unix)]
    {
        fs::rename(home.root(), &moved)?;
        fs::create_dir(home.root())?;
        protect(&home.root())?;
        assert_eq!(
            files
                .readback(&home.root().join("missing"))
                .err()
                .ok_or("replacement admitted")?
                .code,
            StateFileErrorCode::SourceChanged
        );
    }
    #[cfg(windows)]
    {
        // The Windows directory pin denies delete sharing rather than permitting replacement.
        assert!(fs::rename(home.root(), &moved).is_err());
        assert!(files.readback(&home.root().join("missing"))?.is_none());
    }
    Ok(())
}

/// Bug: cad73f5 — ordinary side-file creation did not inherit the protected DACL.
#[cfg(windows)]
#[test]
fn inheriting_side_files_are_accepted_under_the_protected_root() -> Check {
    let home = Home::new()?;
    let files = NativeStateFiles::create(&home.root())?;
    let path = home.root().join("state.db-wal");
    fs::write(&path, b"inheriting side-file bytes")?;
    acl(&path, "owner-self")?;
    acl(&path, "observe-inherited")?;
    assert_eq!(
        read(files.readback(&path)?.ok_or("side file absent")?)?,
        b"inheriting side-file bytes"
    );
    Ok(())
}

/// Bug: cad73f5 — a real file beyond MAX_PATH became measured absence.
#[cfg(windows)]
#[test]
fn long_paths_read_existing_files_and_publish_new_ones() -> Check {
    use std::os::windows::ffi::OsStrExt;
    let home = Home::new()?;
    let files = home.existing()?;
    let mut directory = home.root();
    for n in 0..4 {
        directory.push(format!("owned-{n}-{}", "d".repeat(64)));
        fs::create_dir(&directory)?;
        protect(&directory)?;
    }
    let path = directory.join("state.db");
    fs::write(&path, b"existing long-path image")?;
    protect(&path)?;
    assert!(path.as_os_str().encode_wide().count() > 290);
    assert_eq!(fs::read(&path)?, b"existing long-path image");
    assert_eq!(
        read(
            files
                .readback(&path)?
                .ok_or("existing long file reported absent")?
        )?,
        b"existing long-path image"
    );
    let mut stage = files.create_staging(&directory)?;
    stage.file.write_all(b"new long-path image")?;
    drop(stage.file);
    let published = directory.join("published.db");
    files.publish_no_replace(&stage.path, &published)?;
    assert_eq!(fs::read(&published)?, b"new long-path image");
    Ok(())
}

/// Protects: G8 — reparse points inside the owned root cannot redirect a read.
#[cfg(windows)]
#[test]
fn junction_inside_the_root_refuses_without_claiming_absence() -> Check {
    let home = Home::new()?;
    let files = home.existing()?;
    let target = home.0.join("target");
    fs::create_dir(&target)?;
    protect(&target)?;
    let junction = home.root().join("junction");
    let output = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&target)
        .output()?;
    assert!(
        output.status.success(),
        "junction fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    use std::os::windows::fs::MetadataExt;
    assert_ne!(
        fs::symlink_metadata(&junction)?.file_attributes() & 0x400,
        0
    );
    assert!(files.readback(&junction.join("absent")).is_err());
    Ok(())
}

/// Protects: G8 — unprotected root DACLs refuse even for a missing file.
#[cfg(windows)]
#[test]
fn unprotected_root_dacl_refuses_before_an_absence_read() -> Check {
    let home = Home::new()?;
    let files = home.existing()?;
    acl(&home.root(), "unprotect")?;
    assert!(NativeStateFiles::open(&home.root()).is_err());
    assert!(files.readback(&home.root().join("absent")).is_err());
    Ok(())
}

/// Protects: G8 — a foreign owner is not admitted by an otherwise private DACL.
#[cfg(windows)]
#[test]
#[ignore = "requires an elevated Windows account with SeRestorePrivilege to provision a foreign owner"]
fn foreign_owner_refuses_with_an_otherwise_private_dacl() -> Check {
    let home = Home::new()?;
    let files = home.existing()?;
    let path = home.root().join("foreign.db");
    fs::write(&path, b"foreign owner")?;
    protect(&path)?;
    // This provisioning step needs an administrative test account, not the product.
    acl(&path, "foreign-owner")?;
    acl(&path, "observe-foreign-owner")?;
    assert_eq!(
        files
            .readback(&path)
            .err()
            .ok_or("foreign owner admitted")?
            .code,
        StateFileErrorCode::LocationUnsafe
    );
    Ok(())
}

/// Protects: G8 — an inherited foreign ACE refuses under a protected current parent.
#[cfg(windows)]
#[test]
fn foreign_inherited_ace_refuses_under_a_protected_parent() -> Check {
    let home = Home::new()?;
    let files = home.existing()?;
    let parent = home.0.join("other-parent");
    fs::create_dir(&parent)?;
    protect(&parent)?;
    acl(&parent, "foreign-parent")?;
    let origin = parent.join("foreign.db");
    fs::write(&origin, b"foreign inherited rule")?;
    let moved = home.root().join("moved.db");
    fs::rename(&origin, &moved)?;
    acl(&moved, "observe-foreign-inherited")?;
    assert_eq!(
        files
            .readback(&moved)
            .err()
            .ok_or("foreign inherited ACE admitted")?
            .code,
        StateFileErrorCode::LocationUnsafe
    );
    Ok(())
}

/// Bug: cad73f5 — trusted symlinked system ancestors were rejected as owned children.
#[cfg(unix)]
#[test]
fn user_owned_ancestor_links_are_allowed_but_final_root_links_refuse() -> Check {
    let home = Home::new()?;
    let real = home.0.join("real");
    fs::create_dir(&real)?;
    protect(&real)?;
    let alias = home.0.join("system-alias");
    std::os::unix::fs::symlink(&real, &alias)?;
    assert!(NativeStateFiles::open(&alias).is_err());
    let root = alias.join("state");
    let files = NativeStateFiles::create(&root)?;
    let mut stage = files.create_staging(&root)?;
    stage.file.write_all(b"under a trusted ancestor")?;
    drop(stage.file);
    files.publish_no_replace(&stage.path, &root.join("state.db"))?;
    assert_eq!(
        fs::read(real.join("state/state.db"))?,
        b"under a trusted ancestor"
    );
    Ok(())
}

/// Bug: cad73f5 — a correctly inherited side file was refused even with a protected parent.
#[cfg(windows)]
#[test]
fn independently_inherited_side_file_is_readable_without_write_access() -> Check {
    let home = Home::new()?;
    let files = home.existing()?;
    let path = home.root().join("state.db-shm");
    fs::write(&path, b"independent inherited bytes")?;
    acl(&path, "owner-self")?;
    acl(&path, "observe-inherited")?;
    let mut file = files.readback(&path)?.ok_or("inherited file absent")?;
    assert_eq!(
        file.write_all(b"x")
            .err()
            .ok_or("readback handle writable")?
            .kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(read(file)?, b"independent inherited bytes");
    Ok(())
}
