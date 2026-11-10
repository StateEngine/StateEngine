//! Evented app-server stdio. The binding owns and closes the native transport;
//! this reader owns only bounded framing state and never launches a helper.
use super::wire::{Lines, Message};
use crate::{
    CallContext, HostFuture, ProviderIoPlatform, ProviderStream, ProviderTransport, StreamRead,
};
use se_types::{Result, SeError};
use std::{num::NonZeroU32, sync::Arc, time::Instant};
use zeroize::{Zeroize, Zeroizing};

const READ_CHUNK: NonZeroU32 = match NonZeroU32::new(64 * 1024) {
    Some(value) => value,
    None => unreachable!(),
};

enum Terminal {
    Eof,
    Failed(se_types::ErrorBody),
}

/// At most one incomplete frame plus one native read chunk is retained. A
/// completed frame is dispatched before parsing the remaining chunk suffix.
#[derive(Default)]
pub struct Reader {
    lines: Lines,
    bytes: Zeroizing<Vec<u8>>,
    offset: usize,
    terminal: Option<Terminal>,
    failed: bool,
    chunk_observed_at: Option<Instant>,
    frame_observed_at: Option<Instant>,
    last_observed_at: Option<Instant>,
}
impl Reader {
    pub(crate) fn observed_at(&self) -> Result<Instant> {
        self.last_observed_at
            .ok_or_else(|| invalid("a received native frame before its observation clock"))
    }
    /// Cancelling this future between reads leaves all received bytes in this
    /// reader. A retry uses the original binding and cannot shift a frame.
    pub fn next<'a>(
        &'a mut self,
        io: &'a dyn ProviderIoPlatform,
        transport: &'a ProviderTransport,
        cx: CallContext,
    ) -> HostFuture<'a, Option<Message>> {
        Box::pin(async move {
            let end = Instant::now() + cx.timeout;
            loop {
                if self.failed {
                    return Err(invalid("a new binding after an output failure"));
                }
                if self.offset < self.bytes.len() {
                    self.frame_observed_at = self.frame_observed_at.or(self.chunk_observed_at);
                    let framed = self.lines.feed(&self.bytes[self.offset..]);
                    let (consumed, message) = match framed {
                        Ok(framed) => framed,
                        Err(error) => {
                            self.failed = true;
                            return Err(error);
                        }
                    };
                    self.offset += consumed;
                    if let Some(message) = message {
                        self.last_observed_at = self.frame_observed_at.take();
                        return Ok(Some(message));
                    }
                }
                self.bytes.zeroize();
                self.offset = 0;
                if let Some(terminal) = self.terminal.take() {
                    let framing = self.lines.finish();
                    match terminal {
                        Terminal::Eof => {
                            if framing.is_err() {
                                self.failed = true;
                            }
                            // Keep EOF sticky; callers cannot re-read an ended
                            // pipe and mistake another source for this binding.
                            self.terminal = Some(Terminal::Eof);
                            return framing.map(|()| None);
                        }
                        Terminal::Failed(error) => {
                            self.failed = true;
                            return Err(match framing {
                                Ok(()) => SeError::from(error),
                                Err(_) => se_core::scope::unreadable(
                                    "Codex output",
                                    "native transport failed with an incomplete app-server frame",
                                )
                                .with_cause(SeError::from(error)),
                            });
                        }
                    }
                }
                let timeout = end
                    .checked_duration_since(Instant::now())
                    .filter(|left| !left.is_zero())
                    .ok_or_else(|| invalid("output within the original call deadline"))?;
                let read = io
                    .read(
                        transport,
                        ProviderStream::Output,
                        READ_CHUNK,
                        CallContext {
                            generation: cx.generation,
                            timeout,
                            cancellation: Arc::clone(&cx.cancellation),
                        },
                    )
                    .await;
                self.chunk_observed_at = Some(Instant::now());
                let read = match read {
                    Ok(read) => read,
                    Err(error) => {
                        if !matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(_)) {
                            self.failed = true;
                        }
                        return Err(error);
                    }
                };
                match read {
                    StreamRead::Bytes(bytes) => {
                        if bytes.is_empty() || bytes.len() > READ_CHUNK.get() as usize {
                            self.failed = true;
                            return Err(invalid(
                                "a nonempty native read within its requested byte bound",
                            ));
                        }
                        self.bytes = Zeroizing::new(bytes);
                    }
                    StreamRead::Eof => self.terminal = Some(Terminal::Eof),
                    StreamRead::Failed { bytes, error } => {
                        if bytes.len() > READ_CHUNK.get() as usize {
                            self.failed = true;
                            return Err(invalid(
                                "a failed native read within its requested byte bound",
                            ));
                        }
                        // Dispatch complete messages actually received before
                        // reporting the retained terminal native failure.
                        self.bytes = Zeroizing::new(bytes);
                        self.terminal = Some(Terminal::Failed(error));
                    }
                }
            }
        })
    }
}

fn invalid(expected: &str) -> SeError {
    SeError::invalid("Codex app-server transport", expected)
}

/// Completion means every byte was accepted by the transport, not that input
/// was accepted by the provider. A failed/partial frame is never auto-retried.
pub async fn write(
    io: &dyn ProviderIoPlatform,
    transport: &ProviderTransport,
    bytes: Vec<u8>,
    cx: CallContext,
) -> Result<()> {
    let expected = bytes.len();
    if expected == 0
        || expected > super::wire::MAX_LINE_BYTES + 1
        || bytes.last() != Some(&b'\n')
        || bytes[..expected - 1].contains(&b'\n')
    {
        return Err(invalid("one complete bounded app-server frame"));
    }
    let written = io.write(transport, bytes, cx).await?;
    if let Some(error) = written.failure {
        return Err(se_core::scope::unreadable("Codex input",
            &format!("input transport failed after {} of {expected} frame bytes; preserve the original input for reconciliation",written.completed_bytes))
            .with_cause(SeError::from(error)));
    }
    if written.completed_bytes as usize != expected {
        return Err(se_core::scope::unreadable(
            "Codex input",
            &format!(
                "only {} of {expected} frame bytes were reported written; preserve the original input for reconciliation",
                written.completed_bytes
            ),
        ));
    }
    Ok(())
}
