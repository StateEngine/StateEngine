//! Windows provider stdio (section 40 §3, H04) over se-proc's safe IOCP port.
//! `open` asks se-proc for the provider's streams: the child ends go into the
//! launch, and the host keeps only an arena reference. se-proc owns every
//! kernel buffer; this wrapper starts bounded operations, waits for se-proc's
//! completion nudge, takes each terminal result once and releases it.
//!
//! An operation outlives a timed-out caller. A pending read is resumed by the
//! next read of that stream, so no bytes are lost; a timed-out write is
//! cancelled and its true count awaited briefly, and stdin is retired either
//! way so the provider never sees a spliced frame. `close` drains and releases
//! everything, and can be retried after a failure or timeout.
use crate::{
    CallContext, HostFuture, ProviderIo, ProviderIoPlatform, ProviderStream, ProviderTransport,
    SessionIdentity, StreamRead, StreamWrite,
};
use se_proc::{
    ProcError, ProviderStdioApi, StdioCloseScope, StdioCompletion, StdioConfig, StdioLimits,
    StdioNotice, StdioOutcome, StdioPort, StdioReadStream, StdioSink, StdioTicket,
};
use se_types::{Result, SeError};
use std::{num::NonZeroU32, pin::pin, sync::Arc, time::Duration};
use tokio::{sync::Mutex, sync::Notify, time::Instant};
mod operations;
use operations::{bounded, deadline_exceeded, native, poisoned, port};

/// How long a cancelled write may take to report its true count.
const CANCEL_GRACE: Duration = Duration::from_secs(1);

/// The host's reference to one provider's streams and their outstanding work.
pub(crate) struct Port {
    port: StdioPort,
    wake: Arc<Wake>,
    stdout: Mutex<Reader>,
    stderr: Mutex<Reader>,
    stdin: Mutex<Writer>,
    /// Tickets whose terminal result is not yet released: a timed-out write,
    /// a stdin close nobody waited for, a release that failed. `close` drains.
    unreleased: std::sync::Mutex<Vec<Unreleased>>,
    closed: Mutex<Closing>,
}
#[derive(Default)]
struct Reader {
    /// A read a timed-out caller left running; the next read resumes it.
    pending: Option<StdioTicket>,
    ended: bool,
}
struct Writer {
    open: bool,
    pending: Option<StdioTicket>,
    closing: Option<StdioTicket>,
    finished: bool,
}
#[derive(Default)]
struct Closing {
    /// The All close a timed-out caller left running.
    ticket: Option<StdioTicket>,
    /// Its successful result, kept until every release has succeeded.
    closed: Option<(StdioTicket, se_proc::StdioClosed)>,
    ticket_released: bool,
    done: bool,
}
struct Unreleased {
    ticket: StdioTicket,
    /// The terminal result was already taken; only the release is owed.
    taken: bool,
}

/// se-proc's coalesced completion nudge: wakes every waiter, which then
/// re-reads its own ticket.
struct Wake(Notify);
impl StdioSink for Wake {
    fn notify(&self, _notice: StdioNotice) {
        self.0.notify_waiters();
    }
}

/// Windows implementation of the provider I/O port over a native process
/// runtime that implements se-proc's provider stream API.
pub struct WindowsProviderIo<R> {
    runtime: Arc<R>,
    limits: StdioLimits,
}
impl<R> WindowsProviderIo<R> {
    pub fn new(runtime: Arc<R>, limits: StdioLimits) -> Self {
        Self { runtime, limits }
    }
}

impl<R: ProviderStdioApi + Send + Sync + 'static> ProviderIoPlatform for WindowsProviderIo<R> {
    fn open(
        &self,
        owner: &se_proc::OwnedProcess,
        _identity: &SessionIdentity,
    ) -> Result<ProviderIo> {
        let identity = self
            .runtime
            .stdio_identity(owner)
            .map_err(|e| native("provider process", &e))?;
        let wake = Arc::new(Wake(Notify::new()));
        let stdio = self
            .runtime
            .create_stdio(
                owner,
                StdioConfig {
                    identity,
                    limits: self.limits,
                    notifications: Arc::clone(&wake) as Arc<dyn StdioSink>,
                },
            )
            .map_err(|e| native("provider streams", &e))?;
        Ok(ProviderIo {
            child: stdio.child,
            host: ProviderTransport {
                windows: Some(Port {
                    port: stdio.port,
                    wake,
                    stdout: Mutex::default(),
                    stderr: Mutex::default(),
                    stdin: Mutex::new(Writer {
                        open: true,
                        pending: None,
                        closing: None,
                        finished: false,
                    }),
                    unreleased: std::sync::Mutex::default(),
                    closed: Mutex::default(),
                }),
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
            let port = port(transport)?;
            let (reader, native_stream) = match stream {
                ProviderStream::Output => (&port.stdout, StdioReadStream::Stdout),
                ProviderStream::Error => (&port.stderr, StdioReadStream::Stderr),
                ProviderStream::Input => {
                    return Err(SeError::invalid("provider read", "an output stream"));
                }
            };
            let until = Instant::now() + cx.timeout;
            let mut reader = bounded(&cx, reader.lock()).await?;
            loop {
                if reader.ended {
                    return Ok(StreamRead::Eof);
                }
                if reader.pending.is_none() {
                    reader.pending = Some(
                        self.runtime
                            .begin_read(&port.port, native_stream, maximum_bytes.get())
                            .map_err(|e| native("provider output", &e))?,
                    );
                }
                // The stream retains the accepted ticket across every await,
                // including a caller or harness drain dropping this future.
                let ticket = reader.pending.as_ref().ok_or_else(poisoned)?;
                let Some(completion) = self.settle(port, ticket, until).await? else {
                    return Err(deadline_exceeded(&cx));
                };
                self.release(port, reader.pending.take().ok_or_else(poisoned)?, true);
                let StdioCompletion::Read {
                    bytes,
                    eof,
                    outcome,
                    ..
                } = completion
                else {
                    return Err(SeError::invalid("provider read", "a read completion"));
                };
                match outcome {
                    StdioOutcome::Complete if eof => {
                        reader.ended = true;
                        if bytes.is_empty() {
                            return Ok(StreamRead::Eof);
                        }
                        return Ok(StreamRead::Bytes(bytes));
                    }
                    // An empty completed read is not EOF: read again.
                    StdioOutcome::Complete if bytes.is_empty() => {}
                    StdioOutcome::Complete => return Ok(StreamRead::Bytes(bytes)),
                    // Only close cancels a read; the stream is over either way.
                    StdioOutcome::Cancelled => {
                        reader.ended = true;
                        return Ok(StreamRead::Failed {
                            bytes,
                            error: se_core::scope::unreadable(
                                "provider output",
                                "the read was cancelled because the streams closed",
                            )
                            .body,
                        });
                    }
                    StdioOutcome::Failed(failure) => {
                        reader.ended = true;
                        return Ok(StreamRead::Failed {
                            bytes,
                            error: se_core::scope::unreadable("provider output", &failure.reason)
                                .body,
                        });
                    }
                }
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
            let expected = bytes.len();
            let port = port(transport)?;
            let until = Instant::now() + cx.timeout;
            let mut writer = bounded(&cx, port.stdin.lock()).await?;
            if !writer.open {
                return Err(SeError::invalid("provider input", "an open stdin stream"));
            }
            let ticket = match self.runtime.begin_write(&port.port, bytes) {
                Ok(ticket) => ticket,
                Err(rejected) => {
                    // Nothing was accepted; the stream still cannot be trusted.
                    self.retire_stdin(port, &mut writer);
                    return Ok(StreamWrite {
                        completed_bytes: 0,
                        failure: Some(native("provider input", &rejected.error).body),
                    });
                }
            };
            // A dropped write may have sent a partial frame. Keep its ticket
            // and forbid another frame until the streams have been closed.
            writer.pending = Some(ticket);
            writer.open = false;
            let ticket = writer.pending.as_ref().ok_or_else(poisoned)?;
            let completion = match self.settle(port, ticket, until).await? {
                Some(completion) => completion,
                None => {
                    // Cancel, then wait briefly for the true count: neither the
                    // cancel acknowledgment nor the deadline proves completion.
                    let _ = self.runtime.cancel(ticket);
                    match self
                        .settle(port, ticket, Instant::now() + CANCEL_GRACE)
                        .await?
                    {
                        Some(completion) => completion,
                        None => {
                            self.retire_stdin(port, &mut writer);
                            return Err(deadline_exceeded(&cx));
                        }
                    }
                }
            };
            self.release(port, writer.pending.take().ok_or_else(poisoned)?, true);
            let StdioCompletion::Write {
                written, outcome, ..
            } = completion
            else {
                self.retire_stdin(port, &mut writer);
                return Err(SeError::invalid("provider input", "a write completion"));
            };
            let failure = match outcome {
                StdioOutcome::Complete if written as usize == expected => None,
                StdioOutcome::Complete => {
                    Some(se_core::scope::unreadable("provider input", "short write").body)
                }
                StdioOutcome::Cancelled => Some(deadline_exceeded(&cx).body),
                StdioOutcome::Failed(failure) => {
                    Some(se_core::scope::unreadable("provider input", &failure.reason).body)
                }
            };
            // A stream left mid-frame can never carry another frame: retire it,
            // so the provider sees EOF instead of a spliced message.
            if failure.is_some() {
                self.retire_stdin(port, &mut writer);
            } else {
                writer.open = true;
            }
            Ok(StreamWrite {
                completed_bytes: written,
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
            let port = port(transport)?;
            let until = Instant::now() + cx.timeout;
            let mut writer = bounded(&cx, port.stdin.lock()).await?;
            if writer.finished {
                return Ok(());
            }
            writer.open = false;
            if writer.closing.is_none() {
                // se-proc finishes an accepted write before closing stdin.
                writer.closing = Some(
                    self.runtime
                        .begin_close(&port.port, StdioCloseScope::Stdin)
                        .map_err(|e| native("provider input close", &e))?,
                );
            }
            let ticket = writer.closing.as_ref().ok_or_else(poisoned)?;
            let Some(completion) = self.settle(port, ticket, until).await? else {
                return Err(deadline_exceeded(&cx));
            };
            self.release(port, writer.closing.take().ok_or_else(poisoned)?, true);
            match completion {
                StdioCompletion::Close { result: Ok(_), .. } => {
                    writer.finished = true;
                    Ok(())
                }
                StdioCompletion::Close {
                    result: Err(failure),
                    ..
                } => Err(se_core::scope::unreadable(
                    "provider input close",
                    &failure.reason,
                )),
                _ => Err(SeError::invalid(
                    "provider input close",
                    "a close completion",
                )),
            }
        })
    }
    fn close<'a>(
        &'a self,
        transport: &'a ProviderTransport,
        cx: CallContext,
    ) -> HostFuture<'a, ()> {
        Box::pin(async move {
            let port = port(transport)?;
            let until = Instant::now() + cx.timeout;
            let mut closing = bounded(&cx, port.closed.lock()).await?;
            if closing.done {
                return Ok(());
            }
            if closing.closed.is_none() {
                if closing.ticket.is_none() {
                    closing.ticket = Some(
                        self.runtime
                            .begin_close(&port.port, StdioCloseScope::All)
                            .map_err(|e| native("provider streams close", &e))?,
                    );
                }
                // All-close custody survives a dropped or timed-out close.
                let ticket = closing.ticket.as_ref().ok_or_else(poisoned)?;
                let Some(completion) = self.settle(port, ticket, until).await? else {
                    return Err(deadline_exceeded(&cx));
                };
                let ticket = closing.ticket.take().ok_or_else(poisoned)?;
                match completion {
                    StdioCompletion::Close {
                        result: Ok(witness),
                        ..
                    } => closing.closed = Some((ticket, witness)),
                    StdioCompletion::Close {
                        result: Err(failure),
                        ..
                    } => {
                        self.release(port, ticket, true);
                        return Err(se_core::scope::unreadable(
                            "provider streams close",
                            &failure.reason,
                        ));
                    }
                    _ => {
                        self.release(port, ticket, true);
                        return Err(SeError::invalid(
                            "provider streams close",
                            "a close completion",
                        ));
                    }
                }
            }
            for reader in [&port.stdout, &port.stderr] {
                let mut reader = bounded(&cx, reader.lock()).await?;
                reader.ended = true;
                if let Some(pending) = reader.pending.take() {
                    self.owe(port, pending, false);
                }
            }
            {
                let mut writer = bounded(&cx, port.stdin.lock()).await?;
                writer.open = false;
                writer.finished = true;
                for ticket in [writer.pending.take(), writer.closing.take()]
                    .into_iter()
                    .flatten()
                {
                    self.owe(port, ticket, false);
                }
            }
            // Every operation is terminal after the All close; release each,
            // keeping any that fail owed to the next close.
            let owed = std::mem::take(&mut *port.unreleased.lock().map_err(|_| poisoned())?);
            let mut failed = None;
            for Unreleased { ticket, taken } in owed {
                if !taken && let Err(error) = self.runtime.take_completion(&ticket) {
                    failed.get_or_insert(error);
                    self.owe(port, ticket, false);
                } else if let Err(error) = self.runtime.release_operation(&ticket) {
                    failed.get_or_insert(error);
                    self.owe(port, ticket, true);
                }
            }
            if let Some(error) = failed {
                return Err(native("provider stream release", &error));
            }
            let state = &mut *closing;
            let Some((ticket, witness)) = state.closed.as_ref() else {
                return Err(SeError::invalid(
                    "provider streams close",
                    "a close witness",
                ));
            };
            if !state.ticket_released {
                self.runtime
                    .release_operation(ticket)
                    .map_err(|e| native("provider streams close", &e))?;
                state.ticket_released = true;
            }
            self.runtime
                .release_stdio(&port.port, witness)
                .map_err(|e| native("provider streams release", &e))?;
            closing.done = true;
            Ok(())
        })
    }
}

#[cfg(test)]
mod independent_cancellation;
