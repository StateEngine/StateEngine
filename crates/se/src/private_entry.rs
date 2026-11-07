//! Private installer serialization entries; markers convey no uninstall authority.
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
