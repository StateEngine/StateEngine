//! The open seam keeps NOFOLLOW on Unix: a symlinked final name is refused
//! behind a trusted ancestor, while a real final file still opens.
#![cfg(unix)]
use super::{ConnectionRole, open};
use crate::cache::{DatabaseFile, DatabasePin};
use std::{
    error::Error,
    io,
    os::unix::fs::symlink,
    time::{Duration, Instant},
};
// A std-only fixture root: the seam test needs no se-proc dependency.
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
            "se-atlas-seam-{}-{}",
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
// The pin's file handle is unused by the open seam; the stub only types the pin.
struct StubFile;
impl DatabaseFile for StubFile {
    fn metadata(&self) -> io::Result<std::fs::Metadata> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "stub pin"))
    }
    fn identity(&self) -> io::Result<crate::cache::DatabaseFileIdentity> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "stub pin"))
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
    let pin = DatabasePin {
        file: Box::new(StubFile),
        path: alias.join("db.sqlite"),
    };
    let deadline = Instant::now() + Duration::from_secs(60);
    let opened = open(&pin, ConnectionRole::HostReader, deadline);
    assert!(
        opened.is_ok(),
        "trusted ancestor with a real final file refused: {opened:?}"
    );
    drop(opened);
    let linked_name = real.join("linked.sqlite");
    symlink(real.join("db.sqlite"), &linked_name)?;
    let pin = DatabasePin {
        file: Box::new(StubFile),
        path: alias.join("linked.sqlite"),
    };
    let refused = open(&pin, ConnectionRole::HostReader, deadline);
    assert!(
        refused.is_err(),
        "a symlinked final name opened at the seam"
    );
    Ok(())
}
