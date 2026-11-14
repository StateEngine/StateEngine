//! Unix provider stdio (section 40 §3, H04). `open` creates three anonymous
//! pipes with the standard library: the child ends go to se-proc through
//! `bind_stdio` before exec, and the host keeps only its own ends, registered
//! with the supplied runtime's reactor. Because the host holds no child end,
//! EOF on output means the provider really closed it. No unsafe code.
//!
//! Every operation is bounded by its CallContext timeout. CallContext
//! cancellation is not observable yet (its state type is still opaque), so a
//! cancelled caller waits for that bound rather than being told it was heard.
use crate::{
    CallContext, HostFuture, ProviderIo, ProviderIoPlatform, ProviderStream, ProviderTransport,
    SessionIdentity, StreamRead, StreamWrite,
};
use se_types::{Result, SeError};
use std::{num::NonZeroU32, os::fd::OwnedFd};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::unix::pipe,
    sync::Mutex,
};

/// The host's ends. Each stream allows one operation at a time; `None` means
/// closed by `finish_input` or `close`, never reopened.
pub(crate) struct Pipes {
    stdin: Mutex<Option<pipe::Sender>>,
    stdout: Mutex<Option<pipe::Receiver>>,
    stderr: Mutex<Option<pipe::Receiver>>,
}

/// Unix implementation of the provider I/O port. Construct inside the
/// supplied runtime: pipe registration needs its reactor.
pub struct UnixProviderIo;

impl ProviderIoPlatform for UnixProviderIo {
    fn open(
        &self,
        _owner: &se_proc::OwnedProcess,
        _identity: &SessionIdentity,
    ) -> Result<ProviderIo> {
        // Anonymous pipes reach only the child se-proc launches; the owner
        // reference proves the prepared scope exists, nothing to bind here.
        let (stdin_child, stdin_host) = std::io::pipe().map_err(|e| io("stdin pipe", e))?;
        let (stdout_host, stdout_child) = std::io::pipe().map_err(|e| io("stdout pipe", e))?;
        let (stderr_host, stderr_child) = std::io::pipe().map_err(|e| io("stderr pipe", e))?;
        let pipes = Pipes {
            stdin: Mutex::new(Some(
                pipe::Sender::from_owned_fd(OwnedFd::from(stdin_host))
                    .map_err(|e| io("stdin registration", e))?,
            )),
            stdout: Mutex::new(Some(
                pipe::Receiver::from_owned_fd(OwnedFd::from(stdout_host))
                    .map_err(|e| io("stdout registration", e))?,
            )),
            stderr: Mutex::new(Some(
                pipe::Receiver::from_owned_fd(OwnedFd::from(stderr_host))
                    .map_err(|e| io("stderr registration", e))?,
            )),
        };
        Ok(ProviderIo {
            child: se_proc::StandardIo {
                stdin: Some(std::fs::File::from(OwnedFd::from(stdin_child))),
                stdout: Some(std::fs::File::from(OwnedFd::from(stdout_child))),
                stderr: Some(std::fs::File::from(OwnedFd::from(stderr_child))),
            },
            host: ProviderTransport {
                unix: Some(pipes),
                _private: (),
            },
        })
    }
    fn read<'a>(
        &'a self,
        transport: &'a ProviderTransport,
        stream: ProviderStream,
        maximum_bytes: NonZeroU32,
        cx: CallContext,
    ) -> HostFuture<'a, StreamRead> {
        Box::pin(async move {
            let pipes = pipes(transport)?;
            let receiver = match stream {
                ProviderStream::Output => &pipes.stdout,
                ProviderStream::Error => &pipes.stderr,
                ProviderStream::Input => {
                    return Err(SeError::invalid("provider read", "an output stream"));
                }
            };
            let mut guard = bounded(&cx, receiver.lock()).await?;
            let Some(receiver) = guard.as_mut() else {
                return Ok(StreamRead::Eof);
            };
            let mut buffer = vec![0; maximum_bytes.get() as usize];
            match bounded(&cx, receiver.read(&mut buffer)).await? {
                Ok(0) => Ok(StreamRead::Eof),
                Ok(count) => {
                    buffer.truncate(count);
                    Ok(StreamRead::Bytes(buffer))
                }
                Err(error) => Ok(StreamRead::Failed {
                    bytes: Vec::new(),
                    error: io("provider output", error).body,
                }),
            }
        })
    }
    fn write<'a>(
        &'a self,
        transport: &'a ProviderTransport,
        bytes: Vec<u8>,
        cx: CallContext,
    ) -> HostFuture<'a, StreamWrite> {
        Box::pin(async move {
            let limit = crate::client::wire::MAX_FRAME_BYTES;
            if bytes.len() > limit {
                return Err(SeError::too_large("provider input", limit, bytes.len()));
            }
            let pipes = pipes(transport)?;
            let mut guard = bounded(&cx, pipes.stdin.lock()).await?;
            let Some(sender) = guard.as_mut() else {
                return Err(SeError::invalid("provider input", "an open stdin stream"));
            };
            // Report the bytes actually accepted, so a partial frame is never
            // mistaken for a written one. Each write gets only the time left.
            let until = tokio::time::Instant::now() + cx.timeout;
            let mut completed = 0usize;
            let mut failure = None;
            while completed < bytes.len() {
                match tokio::time::timeout_at(until, sender.write(&bytes[completed..])).await {
                    Ok(Ok(0)) => {
                        failure =
                            Some(io("provider input", std::io::ErrorKind::WriteZero.into()).body);
                        break;
                    }
                    Ok(Ok(count)) => completed += count,
                    Ok(Err(error)) => {
                        failure = Some(io("provider input", error).body);
                        break;
                    }
                    Err(_) => {
                        failure = Some(deadline_exceeded(&cx).body);
                        break;
                    }
                }
            }
            // A stream left mid-frame can never carry another frame: retire it,
            // so the provider sees EOF instead of a spliced message.
            if failure.is_some() {
                guard.take();
            }
            // Bounded by the 1 MiB frame cap checked above.
            let completed_bytes = u32::try_from(completed)
                .map_err(|_| SeError::too_large("provider input", limit, completed))?;
            Ok(StreamWrite {
                completed_bytes,
                failure,
            })
        })
    }
    fn finish_input<'a>(
        &'a self,
        transport: &'a ProviderTransport,
        cx: CallContext,
    ) -> HostFuture<'a, ()> {
        Box::pin(async move {
            let pipes = pipes(transport)?;
            let mut guard = bounded(&cx, pipes.stdin.lock()).await?;
            if let Some(mut sender) = guard.take() {
                bounded(&cx, sender.flush())
                    .await?
                    .map_err(|e| io("provider input flush", e))?;
            }
            Ok(())
        })
    }
    fn close<'a>(
        &'a self,
        transport: &'a ProviderTransport,
        cx: CallContext,
    ) -> HostFuture<'a, ()> {
        Box::pin(async move {
            let pipes = pipes(transport)?;
            bounded(&cx, pipes.stdin.lock()).await?.take();
            bounded(&cx, pipes.stdout.lock()).await?.take();
            bounded(&cx, pipes.stderr.lock()).await?.take();
            Ok(())
        })
    }
}

fn pipes(transport: &ProviderTransport) -> Result<&Pipes> {
    transport
        .unix
        .as_ref()
        .ok_or_else(|| SeError::invalid("provider transport", "one opened by this platform"))
}

async fn bounded<T>(cx: &CallContext, work: impl std::future::Future<Output = T>) -> Result<T> {
    tokio::time::timeout(cx.timeout, work)
        .await
        .map_err(|_| deadline_exceeded(cx))
}

fn deadline_exceeded(cx: &CallContext) -> SeError {
    SeError::new(se_types::Detail::DeadlineExceeded(
        se_types::details::DeadlineExceeded {
            op: "provider stream".into(),
            deadline_ms: u64::try_from(cx.timeout.as_millis()).unwrap_or(u64::MAX),
        },
    ))
}

fn io(what: &str, error: std::io::Error) -> SeError {
    se_core::scope::unreadable(what, &error.to_string()).with_cause(error)
}
