//! ACP v1 client transport. The coordinator retains native process ownership;
//! protocol replies cannot prove process exit or durable input acceptance.
mod client;
mod connection;
mod offer;
mod permission;
mod session;
mod turn;
mod wire;

pub use connection::{Connection, Diagnostics, Incoming, Message};
pub use offer::OfferFailure;
pub use permission::{PermissionOption, PermissionPolicy, PermissionRefusal, PermissionView};
pub use session::{Observation, Session};
pub use turn::{CapturedMessage, CompletedTurn, ProvisionalText, TurnItem};

/// Proxy and TLS trust settings a protocol agent needs to reach its provider
/// the way other tools on this machine do. The detached host carries them
/// across its environment boundary and every protocol child inherits them.
pub const NETWORK_ENVIRONMENT: &[&str] = &[
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "NODE_EXTRA_CA_CERTS",
    // Lower-case spellings are distinct variables outside Windows; there the
    // case-insensitive read finds the upper-case value instead.
    #[cfg(not(windows))]
    "https_proxy",
    #[cfg(not(windows))]
    "http_proxy",
    #[cfg(not(windows))]
    "all_proxy",
    #[cfg(not(windows))]
    "no_proxy",
];

/// The network settings present in this process's environment.
pub fn network_environment() -> Vec<(std::ffi::OsString, std::ffi::OsString)> {
    NETWORK_ENVIRONMENT
        .iter()
        .filter_map(|name| std::env::var_os(name).map(|value| ((*name).into(), value)))
        .collect()
}

/// Count the exact frame used by a successful prompt offer, including its newline.
pub fn prompt_frame_bytes(id: u64, conversation: &str, text: &str) -> se_types::Result<u64> {
    connection::request_frame(
        id,
        "session/prompt",
        serde_json::json!({"sessionId":conversation,"prompt":[{"type":"text","text":text}]}),
    )
    .map(|bytes| bytes.len() as u64)
}

fn failure(subject: &str, reason: impl std::fmt::Display) -> se_types::SeError {
    se_core::scope::unreadable(subject, &reason.to_string())
}
