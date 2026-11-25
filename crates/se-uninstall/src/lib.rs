//! Windows system uninstall carrier and protected helper-cleanup custody.
//!
//! Extracted from `se-proc` so Windows uninstall handoff, High-integrity
//! staging, and cleanup debt live in a focused OS crate without process-
//! supervision coupling.

#[cfg(windows)]
mod uninstall;

#[cfg(windows)]
pub use uninstall::{
    HelperCleanupOutcome, NativeUninstallCarrier, UNINSTALL_CARRIER_ENTRY, UninstallHelperCleanup,
    UninstallNativeError, uninstall_carrier_entry,
};

#[cfg(all(test, windows))]
#[path = "../../test-support/windows_policy_common.rs"]
mod windows_policy_fixture;
