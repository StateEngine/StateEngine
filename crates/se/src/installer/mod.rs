//! The one native installer holder prepares admitted paths before its script.
mod args;
mod manifest;
use args::Options;
use se_types::{Result, SeError};
use std::ffi::OsString;
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
