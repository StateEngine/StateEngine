//! The host side of the dedicated Atlas cold worker image: which image the
//! host installs beside the verified CLI, and the entry that image runs.
use se_types::SeError;
use std::{
    env,
    ffi::OsString,
    io,
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
};

/// The private dispatch once the process default file owner is set: the
/// argument shape is checked, then the native containment path runs.
pub fn private_dispatch(args: &[OsString]) -> se_types::Result<u8> {
    if args.len() != 2 {
        return Err(SeError::invalid(
            "Atlas private entry",
            "no public arguments",
        ));
    }
    #[cfg(any(target_os = "linux", windows, target_os = "macos"))]
    {
        crate::atlas_cold::private_entry()
    }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        Err(SeError::invalid(
            "Atlas cold worker",
            "native containment on this platform",
        ))
    }
}
/// Fixed companion name of the verified CLI. Both images install together
/// and share one trust domain, so no lookup or version exchange is needed.
const ATLAS_WORKER_BINARY: &str = "se-atlas-worker";

/// The companion's fixed name on the current platform.
pub fn worker_binary_name() -> &'static str {
    if cfg!(windows) {
        "se-atlas-worker.exe"
    } else {
        ATLAS_WORKER_BINARY
    }
}

/// The cold worker runs only the private entry, so prefer the dedicated
/// worker image installed beside the verified CLI; absent or uninstalled,
/// the CLI itself keeps serving as the worker. A linked or non-regular
/// companion is unusable, because the verified CLI must own every file the
/// worker image can create.
pub fn worker_image(cli: &Path) -> PathBuf {
    let candidate = cli
        .parent()
        .map(|directory| directory.join(worker_binary_name()));
    match candidate {
        Some(path) => match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => path,
            _ => cli.to_path_buf(),
        },
        None => cli.to_path_buf(),
    }
}

/// The worker image's full entry. Misdelivered arguments are refused before
/// any state access, because the host treats a dead or silent worker as a
/// startup failure with the stderr text as its report.
pub fn worker_main() -> ExitCode {
    let args: Vec<_> = env::args_os().collect();
    if args.len() != 2 || args[1] != se_proc::atlas_worker::ENTRY {
        eprintln!("se-atlas-worker: private Atlas cold entry only");
        return ExitCode::from(78);
    }
    // The CLI entry performs the same initialization before worker dispatch;
    // the worker creates cache files, so its default owner must match.
    if let Err(error) = se_proc::initialize_file_creation_owner() {
        let failure = SeError::new(
            se_types::Detail::SourceUnreadable(se_types::details::SourceUnreadable {
                subject: "process default file owner".into(),
                reason: error.to_string(),
                next_step: "Restore access to the current process token and retry the command; no store or configuration file has been opened".into(),
            }),
        )
        .with_cause(error);
        let _ = writeln!(io::stderr(), "{failure}");
        return ExitCode::from(failure.class().exit_code());
    }
    match private_dispatch(&args) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            let _ = writeln!(io::stderr(), "{error}");
            ExitCode::from(error.class().exit_code())
        }
    }
}

#[cfg(test)]
mod worker_image_tests {
    use super::worker_image;
    use se_types::{Result, SeError};
    use std::path::{Path, PathBuf};

    struct FixtureRoot(PathBuf);
    impl FixtureRoot {
        fn new(tag: &str) -> Result<Self> {
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or(0);
            let base = std::env::temp_dir().join(format!(
                "se-worker-image-{}-{stamp}-{tag}",
                std::process::id()
            ));
            std::fs::create_dir(&base).map_err(|error| {
                SeError::invalid("worker image test directory", &error.to_string())
            })?;
            Ok(Self(base))
        }
        fn place(&self, name: &str) -> Result<PathBuf> {
            let path = self.0.join(name);
            std::fs::write(&path, "image")
                .map_err(|error| SeError::invalid("worker image test file", &error.to_string()))?;
            Ok(path)
        }
        fn finish<T>(&self, result: Result<T>) -> Result<T> {
            match &result {
                Ok(_) => {
                    if let Err(error) = std::fs::remove_dir_all(&self.0) {
                        eprintln!(
                            "worker image test fixture retained at {}: {error}",
                            self.0.display()
                        );
                    }
                }
                Err(_) => eprintln!(
                    "worker image test fixture retained at {} because the case failed",
                    self.0.display()
                ),
            }
            result
        }
    }

    fn worker_name() -> &'static str {
        if cfg!(windows) {
            "se-atlas-worker.exe"
        } else {
            super::ATLAS_WORKER_BINARY
        }
    }

    #[test]
    fn worker_image_prefers_the_companion_installed_beside_the_cli() -> Result<()> {
        let base = FixtureRoot::new("prefers")?;
        let cli = base.place("se")?;
        let worker = base.place(worker_name())?;
        let chosen = worker_image(&cli);
        let result = (chosen == worker).then_some(()).ok_or_else(|| {
            SeError::invalid(
                "worker image selection",
                &format!("expected {worker:?}, chose {chosen:?}"),
            )
        });
        base.finish(result)
    }

    #[test]
    fn worker_image_falls_back_to_the_cli_when_the_companion_is_absent() -> Result<()> {
        let base = FixtureRoot::new("falls")?;
        let cli = base.place("se")?;
        let chosen = worker_image(&cli);
        let result = (chosen == cli).then_some(()).ok_or_else(|| {
            SeError::invalid(
                "worker image fallback",
                &format!("expected {cli:?}, chose {chosen:?}"),
            )
        });
        base.finish(result)
    }

    #[cfg(unix)]
    #[test]
    fn worker_image_falls_back_when_the_companion_is_a_link() -> Result<()> {
        let base = FixtureRoot::new("link")?;
        let cli = base.place("se")?;
        let target = base.place("target-image")?;
        std::os::unix::fs::symlink(&target, base.0.join(worker_name()))
            .map_err(|error| SeError::invalid("worker image test link", &error.to_string()))?;
        let chosen = worker_image(&cli);
        let result = (chosen == cli).then_some(()).ok_or_else(|| {
            SeError::invalid(
                "worker image link fallback",
                &format!("expected {cli:?}, chose {chosen:?}"),
            )
        });
        base.finish(result)
    }

    #[test]
    fn worker_image_falls_back_when_the_cli_has_no_parent_directory() -> Result<()> {
        let bare = Path::new("se");
        let chosen = worker_image(bare);
        (chosen == *bare).then_some(()).ok_or_else(|| {
            SeError::invalid(
                "worker image fallback",
                &format!("expected {bare:?}, chose {chosen:?}"),
            )
        })
    }
}
