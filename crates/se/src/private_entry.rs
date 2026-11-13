//! Private native helper and installer entries; markers grant no authority.
use se_types::Result;
use std::ffi::OsString;

/// Installer wrapping is deliberately absent from the public command catalogue.
/// The marker selects native serialization and grants no uninstall authority.
pub fn dispatch_install_hold(args: &[OsString]) -> Option<Result<i32>> {
    match args.get(1).and_then(|value| value.to_str()) {
        Some("__install-hold") => Some(crate::installer::run(args)),
        Some("__install-home-check") => Some(crate::installer::check_home(args)),
        Some("__install-files-check") => Some(crate::installer::check_files(args)),
        Some("__install-sync") => Some(crate::installer::sync_paths(args)),
        Some("__install-publish") => Some(crate::installer::publish_file(args)),
        Some("__install-recovery-check") => Some(crate::installer::check_recovery(args)),
        Some("__install-replace") => Some(crate::installer::replace_installation(args)),
        _ => None,
    }
}

#[cfg(windows)]
pub fn dispatch_console_interrupt(args: &[OsString]) -> Option<Result<u8>> {
    match args.get(1).and_then(|value| value.to_str()) {
        Some(se_proc::CONSOLE_INTERRUPT_ENTRY) => Some((|| {
            if args.len() != 3 {
                return Err(se_types::SeError::invalid(
                    "native console helper",
                    "one original identity",
                ));
            }
            se_proc::console_interrupt_entry(&args[2])
                .map(|dispatch| {
                    if dispatch == se_proc::StopDispatch::Requested {
                        0
                    } else {
                        2
                    }
                })
                .map_err(|cause| {
                    se_core::scope::unreadable("native console cancellation", &format!("{cause:?}"))
                })
        })()),
        _ => None,
    }
}

/// Remove package launch framing only after retaining the actual native creator.
#[cfg(windows)]
pub fn retain_package_parent(mut args: Vec<OsString>) -> std::io::Result<Vec<OsString>> {
    if args.get(1).is_none_or(|arg| arg != "__package-parent") {
        return Ok(args);
    }
    let parent = args
        .get(2)
        .and_then(|value| value.to_str())
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| std::io::Error::other("package wrapper process ID is absent or invalid"))?;
    se_proc::retain_package_parent(parent)?;
    args.drain(1..3);
    Ok(args)
}
