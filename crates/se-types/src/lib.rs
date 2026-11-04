//! Shared product values. No I/O, ambient identity, runtime, clock or random source.
//! Prefer explicit imports for Read, Cursor and Result to avoid std name collisions.
//! Public host-facing contracts are owned by SE Code, not this proprietary crate.
pub mod code;
mod error;
mod hex;
mod id;
mod process;
mod read;
mod receipt;
mod sensitive;
mod surface;
pub use error::*;
pub use hex::hex_lower;
pub use id::*;
pub use process::*;
pub use read::*;
pub use receipt::*;
pub use sensitive::*;
pub use surface::*;
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

/// Shared default and bounds for finite work and its matching store reader budget.
/// Effective one-core execution retains its separate legacy fallback.
pub const DEFAULT_BLOCKING_JOBS: u32 = 2;
pub const MIN_BLOCKING_JOBS: u32 = 2;
pub const MAX_BLOCKING_JOBS: u32 = 8;

/// UTF-8 byte limits shared by operation DTOs and every ingress/store validator.
pub const MESSAGE_BODY_MAX_BYTES: usize = 32 * 1024;
pub const WORKING_STATE_MAX_BYTES: usize = 16 * 1024;

/// Public session.turn transport input; trusted pinned-source capture stages separately.
pub const SESSION_TURN_MAX_CONTENT_BYTES: usize = 128 * 1024;
pub const SESSION_TURN_MAX_METADATA_BYTES: usize = 256 * 1024;
pub const SESSION_TURN_MAX_FRAME_BYTES: usize = 1024 * 1024;
