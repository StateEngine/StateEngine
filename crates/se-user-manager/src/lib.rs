//! Linux systemd user-manager D-Bus FFI for background host lifetime admission.
//!
//! Extracted from `se-proc` so libsystemd/D-Bus dynamic symbol loading and
//! transient user-scope verification live in a focused Linux-only OS crate.

#[cfg(target_os = "linux")]
mod bus;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
mod peer;
#[cfg(target_os = "linux")]
mod symbols;

#[cfg(target_os = "linux")]
pub use linux::{UserScope, admit, pin_launcher, scope_empty, verify};
