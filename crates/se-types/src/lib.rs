//! Compile-only design contracts; no product implementation is included yet.
//! Normative behavior: docs/design/10-types-and-host-api.md.
//! Private fields deliberately have no constructors until design approval.
#![allow(
    dead_code,
    reason = "Signature-only storage; implementation awaits design approval"
)]

pub mod error;
pub mod id;
pub mod process;
pub mod read;
pub mod receipt;

pub use error::*;
pub use id::*;
pub use process::*;
pub use read::*;
pub use receipt::*;

pub type Result<T> = std::result::Result<T, SeError>;
