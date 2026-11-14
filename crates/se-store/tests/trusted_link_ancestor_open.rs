//! A store reached through a trusted symlinked ancestor directory still opens.
//!
//! SQLite's own NOFOLLOW flag refuses a symlinked ancestor outright (extended
//! code 1550, SQLITE_CANTOPEN_SYMLINK), which breaks the ordinary macOS temp
//! directory under /var. The open seam now resolves the same link rule the
//! state-files walk admits: a symlinked ancestor owned by root or by the
//! current user. This test runs wherever the gates run so the shape has a
//! witness on every platform; on macOS the state directory itself is created
//! through the same trusted link (issue 272's directory-probe change).
#![cfg(unix)]
use se_proc::NativeStateFiles;
use se_store::*;
use std::{error::Error, os::unix::fs::symlink, path::PathBuf};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../../test-support/directory.rs"]
mod cleanup_directory;
/// A state home reached through a current-user-owned ancestor link, the
/// production macOS /var shape: the link is an intermediate ancestor and
/// the protected state home itself stays a real directory (a final link is
/// the walk's own refusal, covered by 294's create-walk tests).
fn linked_state() -> Result<(cleanup_directory::PrivateDirectory, PathBuf, PathBuf), Box<dyn Error>>
{
    let root = cleanup_directory::private_case_directory()?;
    let real = root.join("real");
    drop(NativeStateFiles::create(&real.join("state"))?);
    let link = root.join("link");
    symlink(&real, &link)?;
    let state = link.join("state");
    Ok((root, state, real))
}
/// Protects: a store under a trusted link ancestor accepts writes and reads
/// them back, with the database at the real location. An open that did not
/// resolve the link fails at the SQLite seam (extended code 1550).
#[test]
fn store_opens_through_a_trusted_ancestor_link() -> Check {
    let (root, state, real) = linked_state()?;
    let fixture = Fixture::at(root.to_path_buf(), state)?;
    let (direct, lease) = fixture.direct()?;
    let mut read = direct.snapshot(fixture.self_scope(&fixture.a))?;
    let project = present(read.project(fixture.project.clone())?)?;
    assert!(matches!(
        project.current.body,
        EventBody::ProjectRegistered { .. }
    ));
    read.close()?;
    direct.close()?;
    drop(lease);
    let real_db = real.join("state/state.db");
    assert!(
        real_db.is_file(),
        "database absent at the real location behind the link"
    );
    root.finish(Ok(()))
}
