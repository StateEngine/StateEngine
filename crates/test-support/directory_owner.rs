use std::{ops::Deref, path::PathBuf};

/// A private fixture root that removes its whole tree when it goes away.
///
/// Removal runs in `Drop`, so a passing test and a test that fails by returning
/// `Err` both remove their tree. Explicit evidence retention or a panic keeps
/// the tree and names it. A root that cannot be removed is printed too. A forced process termination cannot
/// run `Drop`; creation names the root in captured output for that case.
pub struct PrivateDirectory {
    path: PathBuf,
    retained: bool,
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

impl PrivateDirectory {
    /// Adopt a root that this process created itself, so the same drop-time
    /// cleanup applies. The caller owns the directory: it created it, and it
    /// excludes foreign files. Removal deletes symlinks themselves, not their targets.
    #[allow(dead_code)]
    pub fn adopt(path: PathBuf) -> Self {
        let directory = Self {
            path,
            retained: false,
        };
        eprintln!(
            "fixture root (retained if its process is forcibly terminated): {}",
            directory.path.display()
        );
        directory
    }

    /// Keep evidence when its live process custody could not be closed safely.
    #[allow(dead_code)]
    pub fn retain(mut self, reason: &str) {
        eprintln!("retained fixture root {}: {reason}", self.path.display());
        self.retained = true;
    }

    /// Move only this owned tree and keep cleanup attached to its new name.
    #[allow(dead_code)]
    pub fn rename_to(&mut self, destination: PathBuf) -> std::io::Result<()> {
        match std::fs::symlink_metadata(&destination) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "fixture destination exists; choose a fresh sibling directory",
                ));
            }
        }
        std::fs::rename(&self.path, &destination)?;
        self.path = destination;
        eprintln!(
            "fixture root (retained if its process is forcibly terminated): {}",
            self.path.display()
        );
        Ok(())
    }
}

impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        if self.retained {
            return;
        }
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
        // This process owns the fixture tree. Recursive removal removes links
        // themselves without following them. An already-absent root is not
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
