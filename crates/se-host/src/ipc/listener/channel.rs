//! Finite evented framing on the supplied runtime.
use super::*;
use std::io;
use tokio::time::{Instant, timeout_at};
use zeroize::Zeroizing;
pub(super) async fn bounded<T>(
    deadline: &Deadline,
    future: impl std::future::Future<Output = T>,
) -> Result<T> {
    deadline.remaining()?;
    let result = timeout_at(Instant::from_std(deadline.at()), future)
        .await
        .map_err(|_| wire::io_failure("IPC absolute deadline", io::ErrorKind::TimedOut.into()))?;
    deadline.remaining()?;
    Ok(result)
}
async fn exact(stream: &NativeStream, mut bytes: &mut [u8], deadline: &Deadline) -> Result<()> {
    while !bytes.is_empty() {
        bounded(deadline, stream.readable())
            .await?
            .map_err(|e| wire::io_failure("wait IPC read", e))?;
        match stream.try_read(bytes) {
            Ok(0) => {
                return Err(wire::io_failure(
                    "incomplete IPC frame",
                    io::ErrorKind::UnexpectedEof.into(),
                ));
            }
            Ok(count) => bytes = &mut bytes[count..],
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(wire::io_failure("read IPC frame", e)),
        }
    }
    Ok(())
}
pub(super) async fn receive(
    stream: &NativeStream,
    deadline: &Deadline,
    limit: usize,
) -> Result<wire::WireBytes> {
    receive_optional(stream, deadline, limit)
        .await?
        .ok_or_else(|| {
            wire::io_failure("incomplete IPC frame", io::ErrorKind::UnexpectedEof.into())
        })
}
pub(super) async fn receive_optional(
    stream: &NativeStream,
    deadline: &Deadline,
    limit: usize,
) -> Result<Option<wire::WireBytes>> {
    let Some((mut header, count)) = first_header(stream, deadline).await? else {
        return Ok(None);
    };
    exact(stream, &mut header[count..], deadline).await?;
    let mut bytes = Zeroizing::new(vec![0; wire::frame_length(header, limit)?]);
    exact(stream, &mut bytes, deadline).await?;
    Ok(Some(wire::WireBytes::from_owned(bytes)))
}

pub(super) async fn send(
    stream: &NativeStream,
    frame: &wire::WireBytes,
    deadline: &Deadline,
) -> Result<()> {
    let mut bytes = frame.as_bytes();
    while !bytes.is_empty() {
        bounded(deadline, stream.writable())
            .await?
            .map_err(|e| wire::io_failure("wait IPC write", e))?;
        match stream.try_write(bytes) {
            Ok(0) => {
                return Err(wire::io_failure(
                    "incomplete IPC write",
                    io::ErrorKind::WriteZero.into(),
                ));
            }
            Ok(count) => bytes = &bytes[count..],
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(wire::io_failure("write IPC frame", e)),
        }
    }
    Ok(())
}

/// Idle time is independent of the operation budget. The call clock starts at
/// the first frame byte, and bounds the remaining header/body and execution.
pub(super) async fn receive_after_idle(
    stream: &NativeStream,
    idle: &Deadline,
    limit: usize,
) -> Result<Option<(wire::WireBytes, Deadline)>> {
    let Some((mut header, count)) = first_header(stream, idle).await? else {
        return Ok(None);
    };
    let deadline = idle.next_call()?;
    exact(stream, &mut header[count..], &deadline).await?;
    let mut bytes = Zeroizing::new(vec![0; wire::frame_length(header, limit)?]);
    exact(stream, &mut bytes, &deadline).await?;
    Ok(Some((wire::WireBytes::from_owned(bytes), deadline)))
}
async fn first_header(stream: &NativeStream, idle: &Deadline) -> Result<Option<([u8; 4], usize)>> {
    let mut header = [0; 4];
    loop {
        bounded(idle, stream.readable())
            .await?
            .map_err(|error| wire::io_failure("wait IPC header", error))?;
        match stream.try_read(&mut header) {
            Ok(0) => return Ok(None),
            Ok(count) => return Ok(Some((header, count))),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            // Windows signals orderly pipe disconnect through BrokenPipe;
            // before a frame begins it has the same meaning as Unix EOF.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::NotConnected
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(wire::io_failure("read IPC header", error)),
        }
    }
}
