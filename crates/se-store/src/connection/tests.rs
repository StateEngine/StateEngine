//! The open seam keeps NOFOLLOW on Unix: a symlinked final name is refused
//! behind a trusted ancestor, while a real final file still opens.
#![cfg(unix)]
use super::open;
use rusqlite::OpenFlags;
use std::{error::Error, os::unix::fs::symlink};
// A std-only fixture root: the seam test needs no state-file custody, and the
// shared directory helper is already a module of this crate through the
// trusted_path tests.
struct TempRoot(std::path::PathBuf);
impl std::ops::Deref for TempRoot {
    type Target = std::path::Path;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl TempRoot {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "se-store-seam-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir(&dir)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self(dir))
    }
}
impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn unix_open_refuses_a_symlinked_final_name_behind_a_trusted_ancestor() -> Result<(), Box<dyn Error>>
{
    let root = TempRoot::new()?;
    let real = root.join("real");
    std::fs::create_dir(&real)?;
    // A real database at the real location: the refusal is about the name,
    // not the content.
    {
        let db = rusqlite::Connection::open(real.join("db.sqlite"))?;
        db.execute_batch("CREATE TABLE probe (x INTEGER)")?;
    }
    let alias = root.join("alias");
    symlink(&real, &alias)?;
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY
        | OpenFlags::SQLITE_OPEN_NOFOLLOW
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let opened = open(&alias.join("db.sqlite"), flags);
    assert!(
        opened.is_ok(),
        "trusted ancestor with a real final file refused: {opened:?}"
    );
    drop(opened);
    let linked_name = real.join("linked.sqlite");
    symlink(real.join("db.sqlite"), &linked_name)?;
    let refused = open(&alias.join("linked.sqlite"), flags);
    assert!(
        refused.is_err(),
        "a symlinked final name opened at the seam"
    );
    Ok(())
}
