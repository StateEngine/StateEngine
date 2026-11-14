use std::{
    ops::Deref,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
};
#[path = "directory_binding.rs"]
mod binding;

/// Own a created fixture root, its native identity, and cleanup authorization.
/// A case owner keeps returned-error evidence until its final result succeeds.
/// Forced termination cannot run Drop; creation always names the root.
pub struct PrivateDirectory {
    path: PathBuf,
    binding: std::io::Result<binding::Binding>,
    completed: AtomicBool,
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
    /// Existing fixture factories retain their established drop-time policy.
    /// Newly managed cases use for_case and authorize cleanup at final success.
    #[allow(dead_code)]
    pub fn adopt(path: PathBuf) -> Self {
        let (path, binding) = match binding::Binding::capture(&path) {
            Ok((physical, binding)) => (physical, Ok(binding)),
            Err(error) => (path, Err(error)),
        };
        eprintln!(
            "fixture root (retained if interrupted or cleanup is unproved): {}",
            path.display()
        );
        Self {
            path,
            binding,
            completed: AtomicBool::new(true),
            retained: false,
        }
    }
    #[allow(dead_code)]
    pub fn for_case(path: PathBuf) -> Self {
        Self::adopt(path).until_success()
    }
    #[allow(dead_code)]
    pub fn until_success(self) -> Self {
        self.completed.store(false, Ordering::Relaxed);
        self
    }
    /// Preserve an existing fixture destructor's policy after setup succeeds.
    #[allow(dead_code)]
    pub fn cleanup_on_drop(self) -> Self {
        self.completed.store(true, Ordering::Relaxed);
        self
    }
    /// Call only with the complete case result, after native closure succeeds.
    /// Early ? returns and panics never grant cleanup authorization.
    #[allow(dead_code)]
    pub fn finish<T, E>(&self, result: Result<T, E>) -> Result<T, E> {
        self.completed.store(result.is_ok(), Ordering::Relaxed);
        result
    }
    #[allow(dead_code)]
    pub fn keep(&self, reason: &str) {
        self.completed.store(false, Ordering::Relaxed);
        eprintln!("retained fixture root {}: {reason}", self.path.display());
    }
    #[allow(dead_code)]
    pub fn retain(mut self, reason: &str) {
        eprintln!("retained fixture root {}: {reason}", self.path.display());
        self.retained = true;
    }
    /// Move this owned tree and rebind its new name to the same native root.
    #[allow(dead_code)]
    pub fn rename_to(&mut self, destination: PathBuf) -> std::io::Result<()> {
        let binding = self
            .binding
            .as_ref()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        binding.check()?;
        let identity = binding.identity()?;
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
        // An unsuccessful rebind must leave the moved tree named and retained.
        self.binding = Err(std::io::Error::other(
            "moved fixture root has not been rebound",
        ));
        let (physical, binding) = binding::Binding::capture(&self.path)?;
        if binding.identity()? != identity {
            return Err(std::io::Error::other(
                "moved fixture root differs from its original native identity",
            ));
        }
        self.path = physical;
        self.binding = Ok(binding);
        eprintln!(
            "fixture root (retained if interrupted or cleanup is unproved): {}",
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
        if std::thread::panicking() || !self.completed.load(Ordering::Relaxed) {
            eprintln!(
                "retained fixture root after incomplete or failed case: {}",
                self.path.display()
            );
            return;
        }
        let result = (|| {
            self.binding
                .as_ref()
                .map_err(|e| std::io::Error::other(e.to_string()))?
                .check()?;
            std::fs::remove_dir_all(&self.path)
        })();
        if let Err(error) = result {
            eprintln!(
                "fixture cleanup refused or failed at original root {}: {error}",
                self.path.display()
            );
        }
    }
}
