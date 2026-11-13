//! Stream bytes only wake canonical readers. A lost stdout retires its drain;
//! neither EOF nor output JSON is evidence of input acceptance or client death.
use super::{managed::Binding, unreadable};
use crate::{CallContext, ProviderStream, StreamRead};
use se_types::Result;
use std::{
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;

#[derive(Default)]
pub(crate) struct Completion {
    changed: AtomicBool,
    wake: Mutex<Option<Weak<Notify>>>,
}
impl Completion {
    pub(crate) fn arm(&self, wake: &Arc<Notify>) -> Result<()> {
        *self
            .wake
            .lock()
            .map_err(|_| unreadable("SE Code stream wake", "poisoned binding"))? =
            Some(Arc::downgrade(wake));
        if self.changed.load(Ordering::Acquire) {
            wake.notify_one();
        }
        Ok(())
    }
    pub(crate) fn take(&self) -> bool {
        self.changed.swap(false, Ordering::AcqRel)
    }
    pub(crate) fn nudge(&self) {
        self.changed.store(true, Ordering::Release);
        if let Ok(wake) = self.wake.lock()
            && let Some(wake) = wake.as_ref().and_then(Weak::upgrade)
        {
            wake.notify_one();
        }
    }
}
#[derive(Default)]
pub(crate) struct Diagnostics {
    pub recovered: bool,
    pub output_closed: bool,
    pub error_closed: bool,
    pub failure: Option<se_types::ErrorBody>,
    pub stderr: Vec<u8>,
    pub omitted_stderr_bytes: u64,
}
impl Diagnostics {
    fn stderr(&mut self, bytes: &[u8]) {
        const LIMIT: usize = 65536;
        let retained = bytes.len().min(LIMIT.saturating_sub(self.stderr.len()));
        self.stderr.extend_from_slice(&bytes[..retained]);
        self.omitted_stderr_bytes = self
            .omitted_stderr_bytes
            .saturating_add((bytes.len() - retained) as u64);
    }
}
pub(super) async fn start(binding: &Arc<Binding>, generation: se_types::Generation) {
    let mut drains = binding.drains.lock().await;
    for stream in [ProviderStream::Output, ProviderStream::Error] {
        let copied = binding.clone();
        drains.push(tokio::spawn(async move {
            drain(copied, stream, generation).await;
        }));
    }
}
async fn drain(binding: Arc<Binding>, stream: ProviderStream, generation: se_types::Generation) {
    let mut pending = Vec::new();
    const MAXIMUM: usize = 4 * 1024 * 1024;
    loop {
        let cx = CallContext {
            generation,
            timeout: Duration::from_secs(86400),
            cancellation: Arc::new(crate::CancellationState { _private: () }),
        };
        let read = binding
            .io
            .read(
                &binding.transport,
                stream,
                std::num::NonZeroU32::new(65536).unwrap_or(std::num::NonZeroU32::MIN),
                cx,
            )
            .await;
        let failure = match read {
            Ok(StreamRead::Bytes(bytes)) => {
                if stream == ProviderStream::Error {
                    if let Ok(mut diagnostics) = binding.diagnostics.lock() {
                        diagnostics.stderr(&bytes);
                    }
                } else {
                    for part in bytes.split_inclusive(|byte| *byte == b'\n') {
                        if part.len() > MAXIMUM.saturating_sub(pending.len()) {
                            fail(
                                &binding,
                                unreadable(
                                    "SE Code JSONL output",
                                    "frame exceeds four MiB; no prefix was accepted",
                                ),
                            );
                            return;
                        }
                        pending.extend_from_slice(part);
                        if part.last() == Some(&b'\n') {
                            if serde_json::from_slice::<serde_json::Value>(&pending).is_err() {
                                fail(
                                    &binding,
                                    unreadable("SE Code JSONL output", "unreadable complete frame"),
                                );
                                return;
                            }
                            pending.clear();
                            if pending.capacity() > 65536 {
                                pending = Vec::new();
                            }
                            binding.completion.nudge();
                        }
                    }
                }
                continue;
            }
            Ok(StreamRead::Eof) => {
                if let Ok(mut diagnostics) = binding.diagnostics.lock() {
                    if stream == ProviderStream::Output {
                        diagnostics.output_closed = true;
                    } else {
                        diagnostics.error_closed = true;
                    }
                }
                // Output transport loss does not retire the independent client
                // or service. Canonical capture remains available over HTTP.
                if stream == ProviderStream::Output && !pending.is_empty() {
                    fail(
                        &binding,
                        unreadable(
                            "SE Code JSONL output",
                            "stdout ended with an incomplete frame",
                        ),
                    );
                } else {
                    binding.completion.nudge();
                }
                return;
            }
            Ok(StreamRead::Failed { bytes, error }) => {
                if stream == ProviderStream::Error
                    && let Ok(mut diagnostics) = binding.diagnostics.lock()
                {
                    diagnostics.stderr(&bytes);
                }
                unreadable(
                    "SE Code stream read",
                    format!("read failed after {} returned bytes and {} buffered frame bytes; the partial output is not an accepted record", bytes.len(), pending.len()),
                ).with_cause(se_types::SeError::from(error))
            }
            Err(error) if matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(_)) => {
                continue;
            }
            Err(error) => error,
        };
        fail(&binding, failure);
        return;
    }
}
fn fail(binding: &Binding, error: se_types::SeError) {
    if let Ok(mut diagnostics) = binding.diagnostics.lock() {
        diagnostics.failure.get_or_insert(error.body);
    }
    binding.completion.nudge();
}
pub(super) async fn close(binding: &Arc<Binding>, cx: &CallContext) -> Result<()> {
    let deadline = crate::client::lease::Deadline::idle()?.stage(cx.timeout)?;
    if binding.drains.lock().await.is_empty() {
        return Ok(());
    }
    binding
        .io
        .close(
            &binding.transport,
            CallContext {
                generation: cx.generation,
                timeout: deadline.remaining()?,
                cancellation: cx.cancellation.clone(),
            },
        )
        .await?;
    let mut drains = binding.drains.lock().await;
    while let Some(mut task) = drains.pop() {
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline.at()), &mut task)
            .await
        {
            Ok(result) => result.map_err(|e| unreadable("SE Code stream join", e))?,
            Err(_) => {
                drains.push(task);
                return Err(unreadable(
                    "SE Code stream join",
                    "original drain remains owned after the caller's bound",
                ));
            }
        }
    }
    Ok(())
}
