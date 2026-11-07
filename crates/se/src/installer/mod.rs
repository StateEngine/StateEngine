//! The one native installer holder prepares admitted paths before its script.
mod args;
mod manifest;
mod replace;
pub use replace::replace_installation;
#[cfg(unix)]
mod recovery;
use args::Options;
use se_types::{Result, SeError};
use std::ffi::OsString;
pub fn check_recovery(args: &[OsString]) -> Result<i32> {
    #[cfg(unix)]
    {
        recovery::check(args)
    }
    #[cfg(not(unix))]
    {
        let _ = args;
        Err(args::invalid("the Unix installation recovery journal"))
    }
}
/// The worker marker alone cannot turn an unsafe existing home into an install.
pub fn check_home(args: &[OsString]) -> Result<i32> {
    if args.len() != 3 {
        return Err(args::invalid("__install-home-check <selected data home>"));
    }
    let home = args::path(&args[2])?;
    if home != crate::bootstrap::state_home(None)? {
        return Err(args::invalid("the selected platform data home"));
    }
    #[cfg(unix)]
    {
        let directories =
            se_proc::NativeInstallationClaim::inherited_created_directories().map_err(native)?;
        se_proc::NativeStateFiles::open(&home).map_err(native)?;
        for directory in directories.iter().rev() {
            println!("{}", directory.display());
        }
        Ok(0)
    }
    #[cfg(not(unix))]
    Err(args::invalid("a Unix native installation worker"))
}

/// Darwin's sync utility has no per-file interface. Flush exact worker paths
/// without treating an asynchronous global sync as a durable ownership claim.
pub fn sync_paths(args: &[OsString]) -> Result<i32> {
    if !(3..=34).contains(&args.len()) {
        return Err(args::invalid("__install-sync <1 to 32 absolute paths>"));
    }
    for value in &args[2..] {
        let path = args::path(value)?;
        let file = std::fs::File::open(&path).map_err(|error| {
            se_core::scope::unreadable(&path.display().to_string(), &error.to_string())
        })?;
        file.sync_all().map_err(|error| {
            se_core::scope::unreadable(&path.display().to_string(), &error.to_string())
        })?;
    }
    Ok(0)
}

/// Claims a final path with link(2), the only atomic no-replace claim: any
/// existing destination, file, directory or link, refuses with its reason, and
/// an existing directory never receives a link inside itself the way the
/// system ln utility places one.
pub fn publish_file(args: &[OsString]) -> Result<i32> {
    if args.len() != 4 {
        return Err(args::invalid("__install-publish <payload> <destination>"));
    }
    let source = args::path(&args[2])?;
    let destination = args::path(&args[3])?;
    match std::fs::hard_link(&source, &destination) {
        Ok(()) => Ok(0),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Err(SeError::new(
            se_types::Detail::StateConflict(se_types::details::StateConflict {
                subject: destination.display().to_string(),
                reason: "the destination already exists".into(),
                next_step: "Preserve the existing path and resolve the conflict before \
                               retrying the installation"
                    .into(),
            }),
        )
        .with_cause(error)),
        Err(error) => Err(SeError::new(se_types::Detail::StateConflict(
            se_types::details::StateConflict {
                subject: "native installation publication".into(),
                reason: format!("{}: {}", destination.display(), error),
                next_step: "Preserve the reported paths and retry after install or uninstall \
                            finishes"
                    .into(),
            },
        ))
        .with_cause(error)),
    }
}

/// Every installed program/asset file must pass the real native owner reader.
pub fn check_files(args: &[OsString]) -> Result<i32> {
    if !(3..=4098).contains(&args.len()) {
        return Err(args::invalid(
            "__install-files-check <1 to 4096 absolute files>",
        ));
    }
    for value in &args[2..] {
        let path = args::path(value)?;
        se_proc::OwnedFile::open(&path)
            .map_err(native)?
            .ok_or_else(|| args::invalid("present native-owned installation files"))?;
    }
    Ok(0)
}

pub fn run(args: &[OsString]) -> Result<i32> {
    let claim = se_proc::NativeInstallationClaim::acquire().map_err(native)?;
    run_claimed(args, &claim)
}
fn run_claimed(args: &[OsString], claim: &se_proc::NativeInstallationClaim) -> Result<i32> {
    let options = Options::parse(args)?;
    let mut creation = se_proc::NativeDirectoryCreation::begin();
    let result = (|| {
        // Read and verify the complete archive before any program directories
        // are created. Its manifest alone supplies the notice directory layout.
        if options.program {
            manifest::prepare(&mut creation)?;
        }
        for profile in &options.profiles {
            creation
                .prepare(
                    profile
                        .parent()
                        .ok_or_else(|| args::invalid("a profile parent"))?,
                )
                .map_err(native)?;
        }
        if let Some(directory) = &options.fish {
            creation.prepare(directory).map_err(native)?;
        }
        let files = creation.create(&options.home).map_err(native)?;
        se_proc::NativeStateFiles::open(files.root()).map_err(native)?;
        crate::route::identity::ensure_machine_identity(&options.home)?;
        #[cfg(windows)]
        crate::runtime::helper_cleanup::retry(&files, claim)?;
        claim
            .run_child_with_created_directories(
                &args[options.child],
                &args[options.child + 1..],
                &creation,
            )
            .map_err(native)
    })();
    if !matches!(result, Ok(0)) {
        cleanup(&mut creation);
    }
    result
}
fn native(error: se_proc::StateFileError) -> SeError {
    crate::installation_error::map(error, |error| {
        SeError::new(se_types::Detail::StateConflict(
            se_types::details::StateConflict {
                subject: "native installation preparation".into(),
                reason: error.to_string(),
                next_step:
                    "Preserve the reported paths and retry after install or uninstall finishes"
                        .into(),
            },
        ))
    })
}
fn cleanup(creation: &mut se_proc::NativeDirectoryCreation) {
    for entry in creation.rollback() {
        match entry.result {
            Ok(se_proc::DirectoryRemoval::Removed | se_proc::DirectoryRemoval::AlreadyAbsent) => (),
            Ok(se_proc::DirectoryRemoval::NotEmpty) => eprintln!(
                "Installation cleanup preserved a nonempty directory: {}",
                entry.path.display()
            ),
            Err(error) => eprintln!(
                "Installation directory cleanup pending at {}: {error}",
                entry.path.display()
            ),
        }
    }
}
