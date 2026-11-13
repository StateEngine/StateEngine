//! Saved SSH route data; native process ownership belongs to the host.
use se_types::{Result, SeError};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardConfig {
    pub destination: String,
    pub local: SocketAddr,
    pub remote_port: u16,
    pub command: String,
    pub host: super::RemoteHostId,
}
impl ForwardConfig {
    pub fn validate(&self) -> Result<()> {
        validate_destination(&self.destination)?;
        if !self.local.ip().is_loopback() || self.local.port() == 0 || self.remote_port == 0 {
            return Err(SeError::invalid("SSH forward", "nonzero loopback ports"));
        }
        if self.command.is_empty()
            || self.command.len() > 4096
            || self.command.chars().any(char::is_control)
        {
            return Err(SeError::invalid(
                "SSH command",
                "the saved native connection command",
            ));
        }
        Ok(())
    }
}

/// SSH accepts options and a remote shell command, so a destination must never
/// become either. Configuration aliases, user@host and literal IPs remain valid.
pub fn validate_destination(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 255
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-@:[]".contains(&b))
    {
        return Err(SeError::invalid(
            "SSH destination",
            "an SSH configuration alias or user@host without shell syntax",
        ));
    }
    Ok(())
}
