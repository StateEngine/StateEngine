// Short, exclusively created fixture roots avoid shared redirected temp parents.
use std::{error::Error, ops::Deref, path::PathBuf};

/// A private fixture root that removes its whole tree when it goes away.
///
/// Removal runs in `Drop`, after the test body on success or during unwinding
/// on a panic, so a root can no longer leak into a memory-backed temp parent.
/// A test that fails by returning `Err` still gets a normal drop, so a failing
/// run removes its tree too; the fixture can only keep a tree when the process
/// itself dies without unwinding. The path is printed in that case and whenever
/// the removal fails, so a residue is always named.
pub struct PrivateDirectory {
    path: PathBuf,
}

impl Deref for PrivateDirectory {
    type Target = std::path::Path;
    fn deref(&self) -> &Self::Target {
        &self.path
    }
}

impl AsRef<std::path::Path> for PrivateDirectory {
    fn as_ref(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        // Unwinding is the failure a fixture can observe: keep the tree and
        // print it, so a failing test leaves one named home to read and delete.
        // A passing test and a test that returns `Err` still remove their tree.
        if std::thread::panicking() {
            eprintln!(
                "retained fixture root after failure: {}",
                self.path.display()
            );
            return;
        }
        // A fixture tree is created by this process and holds no links out of
        // it, so removing it recursively is safe. An already-absent root is not
        // an error: a caller may also have removed it by hand.
        match std::fs::remove_dir_all(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            // The tree is still there: name it so the residue can be found and
            // deleted. Nothing here may panic while an original failure is
            // already unwinding, so this is a message, not a second panic.
            Err(error) => eprintln!(
                "retained fixture root {}: cleanup failed: {error}",
                self.path.display()
            ),
        }
    }
}

pub fn private_directory() -> Result<PrivateDirectory, Box<dyn Error>> {
    #[cfg(target_os = "macos")]
    let parent = PathBuf::from("/private/tmp");
    #[cfg(all(unix, not(target_os = "macos")))]
    let parent = PathBuf::from("/tmp");
    #[cfg(windows)]
    let parent = std::env::temp_dir();
    for _ in 0..32 {
        // Eight hex digits leave room for stock hash-addressed socket aliases.
        let mut nonce = [0u8; 4];
        se_proc::fill_entropy(&mut nonce)?;
        let root = parent.join(se_types::hex_lower(&nonce));
        let mut custody = se_proc::NativeDirectoryCreation::begin();
        drop(custody.create(&root)?);
        if custody.paths().contains(&root) {
            return Ok(PrivateDirectory { path: root });
        }
    }
    Err("no fresh private fixture directory was created".into())
}
