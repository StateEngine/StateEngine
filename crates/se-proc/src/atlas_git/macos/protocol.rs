//! Private fixed frames. Neither environment values nor repository data select this protocol.
use super::{clock::Expiry, identity::ProcessPin, invalid};
use se_types::NativePath;
use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
};

const FRAME_BYTES: usize = 65_536;
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Launch {
    pub schema: u8,
    pub nonce: [u8; 32],
    pub expiry: Expiry,
    pub host: ProcessPin,
    pub parent: ProcessPin,
    pub helper: NativePath,
    pub git: NativePath,
    pub control: NativePath,
    pub objects: NativePath,
    pub control_identity: [u8; 32],
    pub object_identity: [u8; 32],
    pub arguments: Vec<String>,
    pub policy: String,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) enum Frame {
    Launch(Box<Launch>),
    Receipt {
        nonce: [u8; 32],
        process: ProcessPin,
    },
    Tree {
        nonce: [u8; 32],
        supervisor: ProcessPin,
        git: ProcessPin,
    },
    Release {
        nonce: [u8; 32],
    },
    Finished {
        nonce: [u8; 32],
        status: i32,
        peak_bytes: u64,
    },
    Refused {
        nonce: [u8; 32],
        reason: String,
        child: Option<ProcessPin>,
        reaped: bool,
    },
}
impl Launch {
    pub(super) fn validate(&self) -> io::Result<()> {
        self.expiry.remaining()?;
        if self.schema != 1
            || self.nonce == [0; 32]
            || self.arguments.len() > 32
            || self
                .arguments
                .iter()
                .any(|s| s.len() > 1024 || s.contains('\0'))
            || self.policy.len() > 32_768
            || self.policy.contains('\0')
        {
            return Err(invalid("invalid closed Git authorization frame"));
        }
        for path in [&self.helper, &self.git, &self.control, &self.objects] {
            if !path.to_local().map_err(io::Error::other)?.is_absolute() {
                return Err(invalid("Git frame paths must be absolute native paths"));
            }
        }
        Ok(())
    }
}
fn exact(stream: &mut UnixStream, bytes: &mut [u8], expiry: Expiry) -> io::Result<()> {
    let mut used = 0;
    while used < bytes.len() {
        stream.set_read_timeout(Some(expiry.remaining()?))?;
        match stream.read(&mut bytes[used..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Git authorization channel closed",
                ));
            }
            Ok(count) => used += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error),
        }
    }
    expiry.remaining()?;
    Ok(())
}
pub(super) fn receive(stream: &mut UnixStream, expiry: Expiry) -> io::Result<Frame> {
    let mut size = [0; 4];
    exact(stream, &mut size, expiry)?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > FRAME_BYTES {
        return Err(invalid("Git private frame exceeds 65536 bytes"));
    }
    let mut bytes = vec![0; size];
    exact(stream, &mut bytes, expiry)?;
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}
pub(super) fn send(stream: &mut UnixStream, frame: &Frame, expiry: Expiry) -> io::Result<()> {
    let bytes = serde_json::to_vec(frame).map_err(io::Error::other)?;
    if bytes.is_empty() || bytes.len() > FRAME_BYTES {
        return Err(invalid("Git private frame exceeds 65536 bytes"));
    }
    let mut buffer = Vec::with_capacity(bytes.len() + 4);
    buffer.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buffer.extend_from_slice(&bytes);
    let mut used = 0;
    while used < buffer.len() {
        stream.set_write_timeout(Some(expiry.remaining()?))?;
        match stream.write(&buffer[used..]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "Git authorization write stopped",
                ));
            }
            Ok(count) => used += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => (),
            Err(error) => return Err(error),
        }
    }
    expiry.remaining()?;
    Ok(())
}
