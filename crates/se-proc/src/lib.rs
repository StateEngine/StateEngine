//! Compile-only process-ownership contract. There is no backend implementation.
//!
//! See docs/design/30-process-ownership.md for normative semantics. The public
//! traits declare future functions without executable stub bodies. Native
//! resource layouts are intentionally opaque; no handle is Clone or Default.

mod error;
mod identity;
mod launch;
mod ownership;
#[cfg(windows)]
mod stdio;

pub use error::*;
pub use identity::*;
pub use launch::*;
pub use ownership::*;
#[cfg(windows)]
pub use stdio::*;
