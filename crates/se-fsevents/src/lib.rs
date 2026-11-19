//! Bounded native file event delivery for macOS.
#[cfg(target_os = "macos")]
mod darwin;
#[cfg(target_os = "macos")]
pub use darwin::Watcher;
