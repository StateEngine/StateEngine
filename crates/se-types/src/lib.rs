//! Shared product values. No I/O, ambient identity, runtime, clock or random source.
//! Prefer explicit imports for Read, Cursor and Result to avoid std name collisions.
//! Public host-facing contracts are owned by SE Code, not this proprietary crate.
mod error;
mod id;
mod process;
mod read;
mod receipt;
mod sensitive;
pub use error::*;
pub use id::*;
pub use process::*;
pub use read::*;
pub use receipt::*;
pub use sensitive::*;
pub type Result<T> = std::result::Result<T, SeError>;
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
pub struct ApiVersion {
    pub major: u16,
    pub minor: u16,
}
/// Internal CLI/IPC version, distinct from Alpha's linked API version ownership.
pub const API_VERSION: ApiVersion = ApiVersion { major: 1, minor: 0 };

/// UTF-8 byte limits shared by operation DTOs and every ingress/store validator.
pub const MESSAGE_BODY_MAX_BYTES: usize = 32 * 1024;
pub const WORKING_STATE_MAX_BYTES: usize = 16 * 1024;
