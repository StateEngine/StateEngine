//! Startup envelope and bounded frame codec, independent of native transport.
use crate::{ProcResult, ProcessIdentity, support::capacity};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub(crate) const MAX_FRAME: usize = 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Argument(#[serde(with = "crate::checkpoint::native_path")] pub(crate) PathBuf);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Frame {
    pub(crate) version: u32,
    pub(crate) parent: ProcessIdentity,
    pub(crate) nonce: [u8; 16],
    #[serde(with = "crate::checkpoint::decimal::u64")]
    pub(crate) deadline_ms: u64,
    pub(crate) arguments: Vec<Argument>,
    #[cfg(windows)]
    pub(crate) handles: [u64; 2],
    #[cfg(windows)]
    pub(crate) broker: Option<ProcessIdentity>,
}

pub(crate) fn write_frame(
    bytes: &[u8],
    mut write: impl FnMut(&[u8]) -> ProcResult<()>,
) -> ProcResult<()> {
    if bytes.len() > MAX_FRAME {
        return Err(capacity("runtime frame bytes", MAX_FRAME as u64));
    }
    write(&(bytes.len() as u32).to_le_bytes())?;
    write(bytes)
}

pub(crate) fn read_frame(mut read: impl FnMut(&mut [u8]) -> ProcResult<()>) -> ProcResult<Vec<u8>> {
    let mut length = [0; 4];
    read(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length > MAX_FRAME {
        return Err(capacity("runtime frame bytes", MAX_FRAME as u64));
    }
    let mut bytes = vec![0; length];
    read(&mut bytes)?;
    Ok(bytes)
}
