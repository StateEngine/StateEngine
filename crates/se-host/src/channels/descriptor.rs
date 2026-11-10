//! Connector setup and limits are native data shared by all user interfaces.
use super::*;
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct ConnectorDescriptor {
    pub connector: Connector,
    pub name: &'static str,
    pub max_text_utf16: usize,
    pub edits: bool,
    pub buttons: bool,
    pub threads: bool,
    pub media: bool,
    pub identity_proof: &'static str,
    pub acknowledgement: &'static str,
    pub reconnect: &'static str,
    pub retention_seconds: Option<u64>,
    pub setup: &'static [SetupField],
    pub instructions: &'static str,
}
#[derive(Clone, Debug, Serialize)]
pub struct SetupField {
    pub key: &'static str,
    pub label: &'static str,
    pub secret: bool,
    pub required: bool,
}
#[derive(Clone, Debug)]
pub struct ActionButton {
    pub label: String,
    pub data: String,
}
