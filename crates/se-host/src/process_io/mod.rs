//! Provider stdio leaves (H04 leaf split): the platform ports that the
//! harness module used to publish from `harness/unix_io.rs` and
//! `harness/windows_io.rs`; the crate root re-exports their provider types.
//! Registered as `process_io` from `lib.rs` because the Linux/Windows-only
//! `process` module cannot parent the Unix leaf on macOS.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(crate) use unix::Pipes;
#[cfg(unix)]
pub use unix::UnixProviderIo;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::Port;
#[cfg(windows)]
pub use windows::WindowsProviderIo;
