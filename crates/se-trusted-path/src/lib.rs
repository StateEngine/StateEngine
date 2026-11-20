//! Resolve trusted symlinked ancestors before opening a database path.
pub use se_native_path::resolve;
#[cfg(all(test, unix))]
use std::{io, path::Path};
#[cfg(all(test, unix))]
mod tests;
