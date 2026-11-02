//! A marker selects the native handoff receiver; it conveys no authority.
use se_types::{Result, SeError};
use std::ffi::{OsStr, OsString};

pub const UNINSTALL_HANDOFF_ENTRY: &str = "--stateengine-private-uninstall-handoff";

/// Called before normal CLI parsing. The receiver must authenticate inherited
/// handles before decoding plan bytes, waiting on a parent or applying effects.
pub fn dispatch(args: &[OsString], receiver: impl FnOnce() -> Result<u8>) -> Option<Result<u8>> {
    if args.get(1).map(OsString::as_os_str) != Some(OsStr::new(UNINSTALL_HANDOFF_ENTRY)) {
        return None;
    }
    Some(if args.len() == 2 {
        receiver()
    } else {
        Err(SeError::invalid(
            "private handoff",
            "the exact authenticated inherited-handle entry without arguments",
        ))
    })
}

#[cfg(not(windows))]
pub fn receive_uninstall_handoff() -> Result<u8> {
    Err(SeError::invalid(
        "private handoff",
        "a Windows authenticated inherited-handle entry",
    ))
}

/// Native authentication precedes plan decoding. The marker itself grants no
/// authority, and this receiver never reports a complete public uninstall.
#[cfg(windows)]
pub fn receive_uninstall_handoff() -> Result<u8> {
    let native_error = |error: se_proc::UninstallNativeError| {
        SeError::new(se_types::Detail::StateConflict(se_types::details::StateConflict {
            subject: "private uninstall handoff".into(),
            reason: format!("{}; pending cleanup: {}", error, error.pending_paths.iter().map(|path| path.display().to_string()).collect::<Vec<_>>().join(", ")),
            next_step: "Preserve the reported installation and pending native artifacts; inspect their actual state before retrying".into(),
        })).with_cause(error)
    };
    let mut helper = se_proc::NativeUninstallHelper::from_process_entry()
        .map_err(native_error)?
        .ok_or_else(|| SeError::invalid("private handoff", "authenticated inherited handles"))?;
    let handoff: crate::runtime::handoff::Plan = serde_json::from_slice(helper.core_plan())
        .map_err(|error| {
            SeError::invalid(
                "private uninstall plan",
                "the closed core-owned installation plan",
            )
            .with_cause(error)
        })?;
    let completion = handoff.prepare(&helper.parent().image)?;
    let plan = completion.installation();
    let canonical_image = se_proc::canonicalize_path(&helper.parent().image).map_err(|error| {
        SeError::invalid(
            "private uninstall image",
            "the pinned original image's current name",
        )
        .with_cause(error)
    })?;
    let mut owns_image = false;
    for file in plan.files() {
        match se_proc::canonicalize_path(&file.path) {
            Ok(path) => owns_image |= path == canonical_image,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => {
                return Err(SeError::new(se_types::Detail::SourceUnreadable(
                    se_types::details::SourceUnreadable {
                        subject: file.path.clone(),
                        reason: error.to_string(),
                        next_step:
                            "Restore access to the exact planned path before retrying uninstall"
                                .into(),
                    },
                ))
                .with_cause(error));
            }
        }
    }
    if !owns_image {
        return Err(SeError::invalid(
            "private uninstall plan",
            "an exact owned file matching the authenticated parent image",
        ));
    }
    completion.record_helper_cleanup(helper.helper_cleanup())?;
    helper.announce_ready().map_err(native_error)?;
    if let Some(directory) = helper.staging_directory() {
        eprintln!(
            "Protected helper staging directory: {}; cleanup remains journaled until outside readback",
            directory.display()
        );
    }
    if let Some((path, reason)) = helper.pending_helper() {
        eprintln!(
            "Helper cleanup pending at {}: {reason}; retry install or uninstall after the helper exits",
            path.display()
        );
    }
    while !helper.poll_parent_exit().map_err(native_error)? {
        // The native envelope owns the finite deadline and exact-instance wait.
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let witness = helper.delete_parent_image().map_err(native_error)?;
    eprintln!(
        "Removed installed image: {} (native parent exit and deletion witnessed)",
        witness.removed_image().display()
    );
    crate::runtime::helper_cleanup::verify(plan.state_home(), witness.helper_cleanup())?;
    if let Some((path, reason)) = witness.pending_helper() {
        eprintln!(
            "Helper cleanup pending at {}: {reason}; retry install or uninstall after the helper exits",
            path.display()
        );
    }
    completion.finish()?;
    Ok(0)
}

/// Installer wrapping is deliberately absent from the public command catalogue.
/// The marker selects native serialization and grants no uninstall authority.
pub fn dispatch_install_hold(args: &[OsString]) -> Option<Result<i32>> {
    match args.get(1).and_then(|value| value.to_str()) {
        Some("__install-hold") => Some(crate::installer::run(args)),
        Some("__install-home-check") => Some(crate::installer::check_home(args)),
        Some("__install-files-check") => Some(crate::installer::check_files(args)),
        Some("__install-sync") => Some(crate::installer::sync_paths(args)),
        _ => None,
    }
}
