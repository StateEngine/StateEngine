//! A lock refusal must say who holds it. An advisory `flock` has no owner query,
//! so without this a same-process holder or a forked child's inherited
//! descriptor reads as a foreign writer.
#![cfg(unix)]
use se_proc::{NativeStateFiles, OwnedFile, StateFileError};
use std::{error::Error, os::unix::io::AsRawFd, path::PathBuf, process::Command};

type Check = Result<(), Box<dyn Error>>;

fn private_root() -> Result<PathBuf, Box<dyn Error>> {
    let mut nonce = [0u8; 8];
    se_proc::fill_entropy(&mut nonce)?;
    let path = std::env::temp_dir().join(format!("lock-holder-{}", se_types::hex_lower(&nonce)));
    NativeStateFiles::create(&path)?;
    Ok(path)
}

fn lock(file: &std::fs::File, operation: i32) -> bool {
    // SAFETY: owned test descriptor; flock only takes or releases an advisory
    // lock and owns no memory.
    unsafe { libc::flock(file.as_raw_fd(), operation) == 0 }
}

fn refusal(record: &std::path::Path) -> StateFileError {
    match OwnedFile::open(record) {
        Ok(_) => panic!("the held lock must refuse the open"),
        Err(error) => error,
    }
}

#[test]
fn refusal_names_the_path_and_this_process_holding_a_descriptor() -> Check {
    let root = private_root()?;
    let record = root.join("record.json");
    std::fs::write(&record, b"record")?;

    // A second descriptor in this same process takes the lock, as a concurrent
    // writer would.
    let held = std::fs::File::open(&root)?;
    assert!(
        lock(&held, libc::LOCK_EX | libc::LOCK_NB),
        "test took the lock"
    );
    let error = refusal(&record);
    let text = error.to_string();
    assert!(
        text.contains("installation object is in use")
            && text.contains(&root.display().to_string()),
        "names the operation and the refused path: {text}"
    );
    assert!(
        text.contains("this process also holds a descriptor"),
        "names the same-process holder: {text}"
    );
    assert!(
        error.is_contended(),
        "remains a measured contention refusal"
    );

    // Between fork and exec a spawned child holds duplicates of every
    // descriptor, so a spawn concurrent with the product's own lock is refused
    // by this process's child. That is the class the parallel endpoint tests
    // hit, and it must not read as a foreign writer.
    let spawner = std::thread::spawn(|| {
        for _ in 0..64 {
            let _ = Command::new("/bin/true").status();
        }
    });
    let mut observed = 0;
    for _ in 0..512 {
        if !lock(&held, libc::LOCK_EX | libc::LOCK_NB) {
            continue; // the spawn's inherited duplicate still holds it
        }
        if let Err(error) = OwnedFile::open(&record) {
            let text = error.to_string();
            assert!(
                text.contains("this process also holds a descriptor"),
                "a refusal in a spawn window names this process: {text}"
            );
            observed += 1;
        }
        let _ = lock(&held, libc::LOCK_UN);
    }
    spawner.join().ok();
    assert!(observed > 0, "the scan observed a real refusal");

    std::fs::remove_dir_all(&root)?;
    Ok(())
}
