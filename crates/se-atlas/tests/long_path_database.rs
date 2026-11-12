//! A valid database must open even where the platform's default VFS refuses a
//! long resolved path.
//!
//! Windows' default SQLite VFS rejects a resolved path over `MAX_PATH` with
//! `SQLITE_CANTOPEN`, whose message is "unable to open database file", so a
//! valid cache under a long data home reads as a corrupt or missing database.
//! Linux reaches the same refusal through the same code path at its own
//! ceiling, which is what this drives: the default VFS must refuse, and the
//! refusal must keep the message a user sees. That is the mechanism the
//! Windows fix removes by selecting `win32-longpath`, which cannot be
//! exercised on Linux.
#![cfg(target_os = "linux")]
use rusqlite::{Connection, OpenFlags};
use std::path::PathBuf;

/// A database path past the default VFS ceiling, built from one long directory
/// component so the file system itself is not what refuses.
fn long_database(label: &str) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    // This process and the clock are enough to keep two runs from colliding;
    // the fixture owns only this directory and removes it.
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let root = std::env::temp_dir().join(format!(
        "se-longpath-{label}-{}-{}",
        std::process::id(),
        stamp.as_nanos()
    ));
    // Nest several components: each stays well inside the file system's
    // per-component limit while the resolved path passes the VFS ceiling.
    let mut deep = root.clone();
    for _ in 0..14 {
        deep.push("directory-segment-of-modest-length");
    }
    std::fs::create_dir_all(&deep)?;
    Ok((root, deep.join("atlas.db")))
}

#[test]
fn the_default_vfs_refusal_a_long_cache_path_hits_keeps_its_cause()
-> Result<(), Box<dyn std::error::Error>> {
    let (root, database) = long_database("ceiling")?;
    let resolved = std::fs::canonicalize(database.parent().ok_or("fixture parent")?)
        .map(|parent| parent.join("atlas.db"))?;
    assert!(
        resolved.to_string_lossy().len() > 512,
        "the fixture path must exceed the default VFS ceiling: {}",
        resolved.display()
    );
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let outcome = Connection::open_with_flags(&database, flags);
    let refusal = match outcome {
        Err(error) => error.to_string(),
        Ok(_) => {
            let _ = std::fs::remove_dir_all(&root);
            return Err("the default VFS accepted a path past its stated ceiling".into());
        }
    };
    assert!(
        refusal.contains("unable to open database file"),
        "the default VFS lost the refusal cause a user sees: {refusal}"
    );
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}
