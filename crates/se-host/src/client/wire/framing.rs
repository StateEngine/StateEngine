//! Exact frame I/O retries EINTR under the original native cancellation bound.
use super::{MAX_FRAME_BYTES, WireBytes, invalid, io_failure};
use crate::client::lease::Deadline;
use se_types::Result;
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

pub fn frame_length(header: [u8; 4], limit: usize) -> Result<usize> {
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > limit || limit > MAX_FRAME_BYTES {
        return Err(invalid("a positive frame length within the byte budget"));
    }
    Ok(length)
}

/// Read an exact frame. EOF (including mid-header/body) remains an error, never
/// an empty operation/result. The native channel applies the absolute deadline.
pub fn read_payload<R: Read>(reader: &mut R, limit: usize) -> Result<WireBytes> {
    read_payload_inner(reader, limit, None)
}
pub(crate) fn read_payload_bounded<R: Read>(
    reader: &mut R,
    limit: usize,
    deadline: &Deadline,
) -> Result<WireBytes> {
    read_payload_inner(reader, limit, Some(deadline))
}
fn read_payload_inner<R: Read>(
    reader: &mut R,
    limit: usize,
    deadline: Option<&Deadline>,
) -> Result<WireBytes> {
    let mut header = [0; 4];
    read_exact_frame(reader, &mut header, "read header", deadline)?;
    let mut payload = Zeroizing::new(vec![0; frame_length(header, limit)?]);
    read_exact_frame(reader, &mut payload, "read body", deadline)?;
    Ok(WireBytes(payload))
}

/// Write a complete already-budgeted frame. Refuse a routing record/payload
/// passed in place of a frame before exposing any of its bytes to the channel.
pub fn write_frame<W: Write>(writer: &mut W, frame: &WireBytes) -> Result<()> {
    write_frame_inner(writer, frame, None)
}
pub(crate) fn write_frame_bounded<W: Write>(
    writer: &mut W,
    frame: &WireBytes,
    deadline: &Deadline,
) -> Result<()> {
    write_frame_inner(writer, frame, Some(deadline))
}
fn write_frame_inner<W: Write>(
    writer: &mut W,
    frame: &WireBytes,
    deadline: Option<&Deadline>,
) -> Result<()> {
    let bytes = frame.as_bytes();
    let header: [u8; 4] = bytes
        .get(..4)
        .ok_or_else(|| invalid("a complete frame"))?
        .try_into()
        .map_err(|_| invalid("a complete frame header"))?;
    if frame_length(header, MAX_FRAME_BYTES)? != bytes.len() - 4 {
        return Err(invalid("a frame with its exact complete body"));
    }
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let count = match writer.write(remaining) {
            Ok(count) => count,
            Err(error) if interrupted(&error, deadline)? => continue,
            Err(error) => return Err(io_failure("write frame", error)),
        };
        if count == 0 {
            return Err(io_failure(
                "incomplete write frame",
                io::ErrorKind::WriteZero.into(),
            ));
        }
        remaining = &remaining[count..];
    }
    loop {
        match writer.flush() {
            Ok(()) => return Ok(()),
            Err(error) if interrupted(&error, deadline)? => continue,
            Err(error) => return Err(io_failure("flush frame", error)),
        }
    }
}

// Native cancellation and a genuine EINTR share Interrupted. Retry only after
// checking the original cancel flag and absolute deadline, without renewing it.
fn interrupted(error: &io::Error, deadline: Option<&Deadline>) -> Result<bool> {
    if error.kind() != io::ErrorKind::Interrupted {
        return Ok(false);
    }
    if let Some(deadline) = deadline {
        deadline.remaining()?;
    }
    Ok(true)
}
fn read_exact_frame<R: Read>(
    reader: &mut R,
    mut bytes: &mut [u8],
    stage: &str,
    deadline: Option<&Deadline>,
) -> Result<()> {
    while !bytes.is_empty() {
        let count = match reader.read(bytes) {
            Ok(count) => count,
            Err(error) if interrupted(&error, deadline)? => continue,
            Err(error) => return Err(io_failure(stage, error)),
        };
        if count == 0 {
            return Err(io_failure(stage, io::ErrorKind::UnexpectedEof.into()));
        }
        bytes = &mut bytes[count..];
    }
    Ok(())
}
