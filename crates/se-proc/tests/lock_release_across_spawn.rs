//! Releasing a native advisory lock must not depend on the descriptor closing.
//!
//! `flock` belongs to the open file description, and a spawned child inherits
//! duplicates of every descriptor between fork and exec. A release that only
//! closes this process's duplicate leaves the lock held by the child's copy, so
//! a concurrent reader in this process is refused. This exercises the public
//! reader repeatedly while a spawner thread runs: with an explicit release it
//! never refuses, and on the previous close-only release it refused often.
#![cfg(unix)]
use se_proc::{NativeStateFiles, OwnedFile};
use std::{
    error::Error,
    process::Command,
    sync::Arc,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Duration,
};

#[path = "../../test-support/directory.rs"]
mod cleanup_directory;

type Check = Result<(), Box<dyn Error>>;

fn private_root() -> Result<cleanup_directory::PrivateDirectory, Box<dyn Error>> {
    let root = cleanup_directory::private_case_directory()?;
    NativeStateFiles::create(&root)?;
    Ok(root)
}

#[test]
fn a_released_lock_is_available_while_another_thread_spawns() -> Check {
    let root = private_root()?;
    let record = root.join("record.json");
    std::fs::write(&record, b"record")?;

    let stop = Arc::new(AtomicBool::new(false));
    let spawns = Arc::new(AtomicU64::new(0));
    let spawner = {
        let (stop, spawns) = (Arc::clone(&stop), Arc::clone(&spawns));
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = Command::new("/bin/true").status();
                spawns.fetch_add(1, Ordering::Relaxed);
            }
        })
    };

    // Take and release the record's lock through the public path, then read it
    // again. A close-only release leaves the child's inherited duplicate able
    // to refuse the second read.
    let mut refusals = 0;
    let mut reads = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        let Some(mut file) = OwnedFile::open(&record)? else {
            return Err("the protected record disappeared".into());
        };
        file.sha256()?;
        drop(file);
        reads += 1;
        if let Err(error) = OwnedFile::open(&record) {
            if error.is_contended() {
                refusals += 1;
            } else {
                return Err(format!("unexpected read failure: {error}").into());
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    spawner.join().ok();
    let spawned = spawns.load(Ordering::Relaxed);
    println!("reads={reads} refusals={refusals} spawns={spawned}");
    assert!(spawned > 0, "the spawner ran");
    assert_eq!(
        refusals, 0,
        "a released lock was refused {refusals} times in {reads} reads while {spawned} children were spawned"
    );

    root.finish(Ok(()))
}

/// The installer claim is the pin's own held lock, and a second holder must be
/// refused while it lives. This keeps the claim path covered: the guard owns
/// the pin's description for the pin's lifetime, so taking the claim can never
/// release it early.
#[test]
fn a_held_installation_claim_refuses_a_second_holder() -> Check {
    let root = private_root()?;
    let record = root.join("claimed-record.json");
    std::fs::write(&record, b"record")?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600))?;

    let mut held = OwnedFile::open(&record)?.ok_or("record missing")?;
    held.claim_installation_record()?;
    let refused = match OwnedFile::open(&record) {
        Ok(Some(mut other)) => other.claim_installation_record().is_err(),
        Ok(None) => return Err("held record disappeared".into()),
        Err(error) => error.is_contended(),
    };
    assert!(refused, "a second claim acquired a held lock");

    drop(held);
    let mut after = OwnedFile::open(&record)?.ok_or("record absent after release")?;
    after.claim_installation_record()?;
    root.finish(Ok(()))
}
