//! Private bootstrap and bounded byte relay; no host operation is dispatched.
use crate::client::{auth, wire};
use se_types::{NativePath, Result, SeError, Secret};
use serde::{Deserialize, Serialize};

pub const BOOTSTRAP_LIMIT: usize = 64 * 1024;
pub const CHUNK_BYTES: usize = 16 * 1024;

#[derive(Serialize, Deserialize)]
pub enum Protocol {
    #[serde(rename = "se.session-runner/v1")]
    V1,
}

/// The launch pipe carries this frame. The capability is freshly generated for
/// this endpoint, never the machine credential and never written to discovery.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub protocol: Protocol,
    /// An encoded parent endpoint supplies its measured native identity and the
    /// reserved address. The child replaces only the owner with its own proof.
    pub parent_endpoint: serde_json::Value,
    /// Actual parent measurements, transferred with continuously retained pins.
    pub parent_image: se_proc::native_ipc::InheritedImageProof,
    pub runner_image: se_proc::native_ipc::InheritedImageProof,
    #[serde(with = "auth::secret_bytes")]
    pub capability: Secret,
    pub executable: NativePath,
    pub arguments: Vec<String>,
}

impl Bootstrap {
    pub(super) fn validate(&self) -> Result<()> {
        if self.capability.expose().len() != 32
            || !self.executable.to_local()?.is_absolute()
            || self.arguments.len() > 256
            || self.arguments.iter().map(String::len).sum::<usize>() > BOOTSTRAP_LIMIT / 2
        {
            return Err(SeError::invalid(
                "runner bootstrap",
                "a fresh 32-byte capability, absolute executable and bounded arguments",
            ));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<wire::WireBytes> {
        self.validate()?;
        wire::encode_frame(self, BOOTSTRAP_LIMIT)
    }
}

#[derive(Serialize)]
pub(super) struct Chunk {
    pub stream: &'static str,
    pub bytes: Vec<u8>,
    pub eof: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Write {
    pub bytes: Vec<u8>,
}
