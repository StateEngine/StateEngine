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
    let plan = &handoff.installation;
    plan.validate()?;
    let canonical_image = std::fs::canonicalize(&helper.parent().image).map_err(|error| {
        SeError::invalid(
            "private uninstall image",
            "the pinned original image's current name",
        )
        .with_cause(error)
    })?;
    let mut owns_image = false;
    for file in &plan.files {
        match std::fs::canonicalize(&file.path) {
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
    let completion = handoff.prepare(&helper.parent().image)?;
    helper.announce_ready().map_err(native_error)?;
    while !helper.poll_parent_exit().map_err(native_error)? {
        // The native envelope owns the finite deadline and exact-instance wait.
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let witness = helper.delete_parent_image().map_err(native_error)?;
    eprintln!(
        "Removed installed image: {} (native parent exit and deletion witnessed)",
        witness.removed_image().display()
    );
    completion.finish()?;
    Ok(0)
}

/// Installer wrapping is deliberately absent from the public command catalogue.
/// The marker selects native serialization and grants no uninstall authority.
pub fn dispatch_install_hold(args: &[OsString]) -> Option<Result<i32>> {
    if args.get(1).map(OsString::as_os_str) != Some(OsStr::new("__install-hold")) {
        return None;
    }
    Some((|| {
        if args.get(2).map(OsString::as_os_str) != Some(OsStr::new("--")) || args.len() < 4 {
            return Err(SeError::invalid(
                "private install hold",
                "__install-hold -- <absolute executable> [arguments...]",
            ));
        }
        let claim = se_proc::NativeInstallationClaim::acquire().map_err(install_error)?;
        claim.run_child(&args[3], &args[4..]).map_err(install_error)
    })())
}
fn install_error(error: se_proc::StateFileError) -> SeError {
    SeError::new(se_types::Detail::StateConflict(
        se_types::details::StateConflict {
            subject: "native installation claim".into(),
            reason: error.to_string(),
            next_step:
                "Retry after install or uninstall finishes; preserve the permanent claim file"
                    .into(),
        },
    ))
    .with_cause(error)
}
