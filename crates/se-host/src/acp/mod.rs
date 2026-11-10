//! ACP v1 client transport. The coordinator retains native process ownership;
//! protocol replies cannot prove process exit or durable input acceptance.
mod connection;
mod wire;

pub use connection::{Connection, Diagnostics, Incoming, Message};

fn failure(subject: &str, reason: impl std::fmt::Display) -> se_types::SeError {
    se_core::scope::unreadable(subject, &reason.to_string())
}
