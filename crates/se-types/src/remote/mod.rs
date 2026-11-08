//! Pure R0 client values (design 45 §§3–6, 47). No authority, I/O or key material.
mod authority;
mod credential;
mod handshake;
mod request;
mod response;
pub use crate::{RemoteDeviceId, RemoteGrantId, RemotePrincipalId};
pub use authority::*;
pub use credential::*;
pub use handshake::*;
pub use request::*;
pub use response::*;

pub const CLIENT_PROTOCOL_MAJOR: u16 = 2;
pub const CLIENT_PROTOCOL_MINOR: u16 = 0;
pub const CLIENT_DATA_PATH: &str = "/stateengine/client/v2";
pub const REMOTE_FRAME_BYTES: usize = 256 * 1024;
pub const REMOTE_PREAUTH_BYTES: usize = 32 * 1024;
pub const REMOTE_REQUEST_BUDGET_BYTES: usize = 64 * 1024;
pub const REMOTE_PAGE_BYTES: usize = 256 * 1024;
pub const REMOTE_MAX_TARGETS: usize = 64;
pub const REMOTE_CLIENT_QUEUE_BYTES: usize = 256 * 1024;
pub const REMOTE_CLIENT_QUEUE_FRAMES: usize = 256;
pub const REMOTE_LIVE_RING_BYTES: usize = 2 * 1024 * 1024;
