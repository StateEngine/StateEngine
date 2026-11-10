//! ACP v1 client transport. The coordinator retains native process ownership;
//! protocol replies cannot prove process exit or durable input acceptance.
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

/// Count the exact frame used by a successful prompt offer, including its newline.
pub(crate) fn prompt_frame_bytes(id: u64, conversation: &str, text: &str) -> se_types::Result<u64> {
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
