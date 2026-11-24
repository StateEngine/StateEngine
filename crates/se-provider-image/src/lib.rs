//! Resolve a provider's installed package launcher to the native image that
//! version probes and owned launches both use, and the package environment
//! that image expects. Only filesystem reads happen here; nothing is started.
use std::{
    io,
    path::{Path, PathBuf},
};

mod codex_package;
pub use codex_package::PackageLaunch;
// Resolve packaged providers before their probe and native ownership setup.
#[cfg(unix)]
mod unix_executable;
// Windows script shims are never treated as executable process images.
#[cfg(windows)]
mod windows_executable;

pub struct ProviderExecutable {
    pub executable: PathBuf,
    pub package: Option<PackageLaunch>,
}
impl ProviderExecutable {
    pub fn direct(executable: PathBuf) -> Self {
        Self {
            executable,
            package: None,
        }
    }
    fn packaged(executable: PathBuf, root: Option<PathBuf>, launcher: &Path) -> io::Result<Self> {
        let package = root
            .map(|root| PackageLaunch::observe(root, &executable, launcher))
            .transpose()?;
        Ok(Self {
            executable,
            package,
        })
    }
}

/// The provider's package launcher at `path`, resolved to its native image and
/// the package environment it needs. `None` means `path` is not a file.
pub fn package_launch(
    path: &Path,
    provider: se_types::Provider,
) -> io::Result<Option<ProviderExecutable>> {
    #[cfg(windows)]
    {
        windows_executable::resolve_package(path, Some(provider))?
            .map(|(image, root)| ProviderExecutable::packaged(image, root, path))
            .transpose()
    }
    #[cfg(unix)]
    {
        let _ = provider;
        match std::fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => match unix_executable::packaged_codex(path)? {
                Some((image, root)) => {
                    se_proc::file_access::require_executable_access(&image)?;
                    ProviderExecutable::packaged(image, Some(root), path).map(Some)
                }
                None => {
                    se_proc::file_access::require_executable_access(path)?;
                    Ok(Some(ProviderExecutable::direct(path.to_path_buf())))
                }
            },
            Ok(_) => Ok(None),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
}

/// The executable image a probe should run for `path`: a packaged Codex
/// launcher resolves to its native payload; anything else must itself be an
/// executable file. `None` means `path` is absent or not a file.
pub fn native_executable(
    path: &Path,
    provider: Option<se_types::Provider>,
) -> io::Result<Option<PathBuf>> {
    #[cfg(windows)]
    {
        windows_executable::resolve(path, provider)
    }
    #[cfg(not(windows))]
    {
        match std::fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => {
                #[cfg(unix)]
                if provider == Some(se_types::Provider::Codex)
                    && let Some((image, _)) = unix_executable::packaged_codex(path)?
                {
                    se_proc::file_access::require_executable_access(&image)?;
                    return Ok(Some(image));
                }
                se_proc::file_access::require_executable_access(path)?;
                Ok(Some(path.to_path_buf()))
            }
            Ok(_) => Ok(None),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
}
