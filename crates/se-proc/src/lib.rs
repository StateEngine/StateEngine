//! Native process contracts and protected state-file custody.
//!
//! See docs/design/30-process-ownership.md for normative semantics. The public
//! process traits remain declarations; NativeStateFiles supplies the real
//! protected staging/readback/publication adapter. Native
//! resource layouts are intentionally opaque; no handle is Clone or Default.

mod error;
mod identity;
mod launch;
mod ownership;
mod state_files;
pub use state_files::{
    NativeStateFiles, ProtectedStateStaging, StateFileError, StateFileErrorCode,
};
#[cfg(windows)]
mod stdio;

pub use error::*;
pub use identity::*;
pub use launch::*;
pub use ownership::*;
#[cfg(windows)]
pub use stdio::*;
