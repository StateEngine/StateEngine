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
