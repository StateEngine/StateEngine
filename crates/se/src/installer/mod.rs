//! The one native installer holder prepares admitted paths before its script.
mod args;
mod manifest;
use args::Options;
use se_types::{Result, SeError};
use std::ffi::OsString;
/// The worker marker alone cannot turn an unsafe existing home into an install.
pub fn check_home(args: &[OsString]) -> Result<i32> {
    if args.len() != 3 {
        return Err(args::invalid("__install-home-check <selected data home>"));
    }
    let home = args::path(&args[2])?;
    if home != crate::bootstrap::state_home(None)? {
        return Err(args::invalid("the selected platform data home"));
    }
    se_proc::NativeStateFiles::open(&home).map_err(native)?;
    Ok(0)
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

pub fn run(args: &[OsString]) -> Result<i32> {
    let options = Options::parse(args)?;
    let claim = se_proc::NativeInstallationClaim::acquire().map_err(native)?;
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
        crate::runtime::helper_cleanup::retry(&files, &claim)?;
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
    SeError::new(se_types::Detail::StateConflict(
        se_types::details::StateConflict {
            subject: "native installation preparation".into(),
            reason: error.to_string(),
            next_step: "Preserve the reported paths and retry after install or uninstall finishes"
                .into(),
        },
    ))
    .with_cause(error)
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
