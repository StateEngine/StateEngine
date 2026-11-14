//! A store reached by a path longer than Win32 `MAX_PATH` still opens.
//!
//! SQLite appends `-wal` and `-shm` to the database name and opens those through
//! its own Win32 calls, so with an ordinary drive path the sidecar open is the
//! first casualty once the path reaches 259 characters (259 plus the terminating
//! NUL is the 260-character `MAX_PATH`). The store now hands SQLite the verbatim
//! (`\\?\`) form, which is not capped.
//!
//! The length that matters is a Windows one. This test also runs on Linux so the
//! same shape has a witness wherever the gates run: if it passes on both, the
//! mechanism is the path form handed to SQLite and not a platform-only branch.
use se_proc::NativeStateFiles;
use se_store::*;
use std::{fs, path::PathBuf};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../../test-support/directory.rs"]
mod cleanup_directory;

/// A fresh store home whose full path is longer than `MAX_PATH` allows.
fn long_home() -> Result<(cleanup_directory::PrivateDirectory, PathBuf), Box<dyn std::error::Error>>
{
    let root = cleanup_directory::private_directory()?;
    let mut deep = root.to_path_buf();
    // Each component stays within a normal filesystem limit; the total is what
    // exceeds MAX_PATH, which is the condition SQLite's sidecar open trips over.
    for index in 0..5 {
        deep = deep.join(format!("component-{index:02}-{}", "p".repeat(48)));
    }
    fs::create_dir_all(&deep)?;
    let home = deep.join("state");
    drop(NativeStateFiles::create(&home)?);
    Ok((root, home))
}

/// Protects: a database at a path past MAX_PATH accepts writes and reads back,
/// which needs its WAL sidecar. A plain drive path fails that sidecar open.
#[test]
fn store_keeps_working_sidecars_beyond_max_path() -> Check {
    let (root, home) = long_home()?;
    let path = home.join("state.db");
    assert!(
        path.as_os_str().len() > 259,
        "fixture path is only {} characters",
        path.as_os_str().len()
    );
    let fixture = Fixture::at(root.to_path_buf(), home.clone())?;
    let (direct, lease) = fixture.direct()?;
    // The fixture's setup already wrote the owner and project through the store,
    // which is a WAL-backed write at this path. Read one back before closing.
    let mut read = direct.snapshot(fixture.self_scope(&fixture.a))?;
    let project = present(read.project(fixture.project.clone())?)?;
    assert!(matches!(
        project.current.body,
        EventBody::ProjectRegistered { .. }
    ));
    read.close()?;
    direct.close()?;
    drop(lease);
    assert!(path.is_file(), "database absent at a long path");
    fs::remove_dir_all(&root)?;
    Ok(())
}
