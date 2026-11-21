//! Bounded JSON encoding/decoding shared by harness transports and IPC wire.
use se_types::{Result, SeError};
use serde::Serialize;
use std::io::{self, Write};
use zeroize::Zeroizing;

pub use se_mcp::wire::{MAX_FRAME_BYTES, MAX_JSON_DEPTH, decode_json};

fn invalid(expected: &str) -> SeError {
    SeError::invalid("IPC frame", expected)
}

/// Protected frame bytes deliberately omit Debug, Clone and Serialize.
/// Copies retained for channel I/O are erased when their buffer is dropped.
pub struct WireBytes(Zeroizing<Vec<u8>>);
impl WireBytes {
    pub fn from_owned(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

struct LimitedBuffer {
    bytes: Zeroizing<Vec<u8>>,
    limit: usize,
}
impl Write for LimitedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("IPC JSON exceeds its byte budget"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ByteCount {
    bytes: usize,
    limit: usize,
}
impl Write for ByteCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len())
            .filter(|total| *total <= self.limit)
            .ok_or_else(|| io::Error::other("IPC JSON exceeds its byte budget"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn encode_json<T: Serialize>(value: &T, limit: usize) -> Result<WireBytes> {
    if limit == 0 || limit > MAX_FRAME_BYTES {
        return Err(invalid("a nonzero budget at most 1 MiB"));
    }
    let mut count = ByteCount { bytes: 0, limit };
    serde_json::to_writer(&mut count, value)
        .map_err(|_| invalid("complete JSON within the negotiated byte budget"))?;
    let mut output = LimitedBuffer {
        bytes: Zeroizing::new(Vec::with_capacity(count.bytes)),
        limit: count.bytes,
    };
    serde_json::to_writer(&mut output, value)
        .map_err(|_| invalid("complete JSON within the negotiated byte budget"))?;
    if output.bytes.len() != count.bytes {
        return Err(invalid(
            "the same JSON byte count during sizing and encoding",
        ));
    }
    Ok(WireBytes(output.bytes))
}
