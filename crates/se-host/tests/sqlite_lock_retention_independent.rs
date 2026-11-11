//! Native file custody must not release a live SQLite connection's process locks.
#![cfg(unix)]
use se_host::state_files::{FilePolicy, Files};
use se_store::*;
use sha2::{Digest, Sha256};
use std::{io::Cursor, path::Path, process::Command, sync::Arc, time::Duration};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[allow(
    dead_code,
    reason = "The shared fixture also serves other native consumers."
)]
#[path = "../../se-store/tests/support/host_fixture.rs"]
mod native;

// SQLite's Unix VFS holds a shared lock in this range while a WAL connection
// remains open. A different process must fail to acquire an exclusive lock.
// Probe the actual kernel lock without opening a second SQLite connection,
// which could itself recover or retire the WAL after a broken custody check.
fn database_lock_held(path: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    let output = Command::new("python3")
        .args([
            "-c",
            "import errno,fcntl,sys\nf=open(sys.argv[1],'r+b')\ntry:\n fcntl.lockf(f,fcntl.LOCK_EX|fcntl.LOCK_NB,510,1073741826,0)\nexcept OSError as e:\n if e.errno not in (errno.EACCES,errno.EAGAIN): raise\n print('held')\nelse:\n fcntl.lockf(f,fcntl.LOCK_UN,510,1073741826,0)\n print('free')\nf.close()",
        ])
        .arg(path)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "outside native lock probe failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    match std::str::from_utf8(&output.stdout)?.trim() {
        "held" => Ok(true),
        "free" => Ok(false),
        other => Err(format!("unrecognized outside lock observation: {other}").into()),
    }
}

fn initialized() -> Result<Fixture, Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let (direct, lease) = f.direct()?;
    direct.close()?;
    drop(lease);
    Ok(f)
}

fn retained_lock(operation: impl FnOnce(&Files, &Path) -> Check) -> Check {
    let f = initialized()?;
    let root = &f.options.state_directory;
    let files = Files::open_with_policy(root, FilePolicy::Host)?;
    let database = root.join("state.db");
    let connection = rusqlite::Connection::open(&database)?;
    connection.execute_batch("PRAGMA journal_mode=WAL; BEGIN IMMEDIATE")?;
    assert!(database_lock_held(&database)?, "SQLite lock was never held");
    operation(&files, root)?;
    assert!(
        database_lock_held(&database)?,
        "native custody released the live SQLite database lock"
    );
    connection.execute_batch("ROLLBACK")?;
    connection.close().map_err(|(_, error)| error)?;
    assert!(
        !database_lock_held(&database)?,
        "outside probe must observe release after the real SQLite close"
    );
    Ok(())
}

#[test]
fn preparing_a_native_staging_directory_preserves_sqlite_locks() -> Check {
    retained_lock(|files, root| {
        files.prepare_directory(&root.join("staging"))?;
        Ok(())
    })
}

#[test]
fn listing_native_owned_files_preserves_sqlite_locks() -> Check {
    retained_lock(|files, root| {
        assert!(
            files
                .list_owned(root, 100)?
                .contains(&root.join("state.db"))
        );
        Ok(())
    })
}

#[test]
fn publishing_and_retiring_a_native_manifest_preserves_sqlite_locks() -> Check {
    retained_lock(|files, root| {
        let path = root.join("manifest.json");
        files.replace_owned(&path, None, b"synthetic manifest")?;
        files.remove_owned(&path, Sha256::digest(b"synthetic manifest").into())?;
        assert!(!path.exists());
        Ok(())
    })
}

#[test]
fn protected_store_open_still_refuses_an_unsafe_database() -> Check {
    use std::os::unix::fs::PermissionsExt;
    let f = initialized()?;
    let root = &f.options.state_directory;
    let port = Port {
        lease: Lease::acquire(root, LeaseMode::DirectClient, Some(f.store.clone()))?,
        files: Files::open(root)?,
    };
    let database = root.join("state.db");
    std::fs::set_permissions(&database, std::fs::Permissions::from_mode(0o644))?;
    match SqliteFactory::open_direct(&f.options, &port) {
        Err(error) => assert!(matches!(
            error.code,
            StoreErrorCode::LocationUnsafe | StoreErrorCode::Unreadable
        )),
        Ok(se_types::Read::Unreadable { .. }) => {}
        _ => return Err("protected store open did not refuse the unsafe database".into()),
    }
    Ok(())
}

#[test]
fn directory_custody_still_refuses_a_replaced_root() -> Check {
    let f = initialized()?;
    let root = &f.options.state_directory;
    let files = Files::open_with_policy(root, FilePolicy::Host)?;
    std::fs::rename(root, f.home.join("original-state"))?;
    drop(se_proc::NativeStateFiles::create(root)?);
    assert!(
        files.prepare_directory(&root.join("staging")).is_err(),
        "lock-safe custody must not accept a replaced root"
    );
    Ok(())
}

struct Port {
    lease: Arc<Lease>,
    files: Files,
}
impl RuntimeLease for Port {
    fn identity(&self) -> StoreResult<LeaseIdentity> {
        self.lease.identity()
    }
    fn files(&self) -> &dyn StateFiles {
        &self.files
    }
}

#[test]
fn actual_host_text_staging_keeps_the_writer_locked_until_drain() -> Check {
    let f = initialized()?;
    let port = Arc::new(Port {
        lease: Lease::acquire(
            &f.options.state_directory,
            LeaseMode::Host,
            Some(f.store.clone()),
        )?,
        files: Files::open_with_policy(&f.options.state_directory, FilePolicy::Host)?,
    });
    let mut host = present(SqliteFactory::open_host(&f.options, &*port)?)?;
    host.record_runtime_ownership(
        f.batch(
            f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
            Some(request("staging-lock-owner")?),
            vec![EventBody::RuntimeOwnerEstablished {
                epoch: native::epoch()?,
                generation: se_types::Generation::new(1)?,
                expected_owner_generation: None,
                expected: Expected::Absent,
                witnesses: vec![],
                recovered: None,
            }],
        )?,
        &*port,
    )?;
    let owner = host.start_writer(native::options(8)?, port.clone())?;
    let client = owner.client();
    let database = f.options.state_directory.join("state.db");
    assert!(
        database_lock_held(&database)?,
        "host writer has no SQLite lock"
    );
    let text = b"synthetic staged conversation";
    let staged = client.stage_text(&mut Cursor::new(text), text.len() as u64, &*port)?;
    assert_eq!(staged.byte_length(), text.len() as u64);
    let retained = database_lock_held(&database)?;
    drop(staged);
    drop(native::wait(owner.drain(Duration::from_secs(5)))??);
    drop(client);
    drop(port);
    assert!(
        retained,
        "actual host text staging released the live SQLite database lock"
    );
    assert!(
        !database_lock_held(&database)?,
        "drained writer did not release its SQLite database lock"
    );
    Ok(())
}
