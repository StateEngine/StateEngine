//! Provider framing, output drains and bounded executable probes.
use super::{Binding, READ_CHUNK, claude};
use crate::{CallContext, ProviderStream, StreamRead};
use se_types::{Body, Result, SeError};
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

pub(super) async fn write_frame(binding: &Binding, body: &Body, cx: &CallContext) -> Result<()> {
    let frame = claude::input_frame(body)?;
    let expected = frame.len();
    let written = binding
        .io
        .write(&binding.transport, frame, copy(cx))
        .await?;
    match written.failure {
        // A frame counts as written only when all of its bytes were accepted.
        None if written.completed_bytes as usize == expected => Ok(()),
        None => Err(SeError::invalid(
            "Claude input",
            "the complete stream-json frame",
        )),
        Some(error) => Err(SeError::from(error)),
    }
}

/// Keep one output stream flowing until the provider closes it. Bytes are
/// activity, not captured turns, so they are read and released.
pub(super) async fn drain(
    binding: Arc<Binding>,
    stream: ProviderStream,
    generation: se_types::Generation,
    initial: Vec<u8>,
) {
    let mut frames = super::completion::Frames::default();
    if stream == ProviderStream::Output {
        frames.push(&initial, &binding);
    }
    loop {
        let cx = CallContext {
            generation,
            timeout: Duration::from_secs(24 * 60 * 60),
            cancellation: Arc::new(crate::CancellationState { _private: () }),
        };
        match binding
            .io
            .read(&binding.transport, stream, READ_CHUNK, cx)
            .await
        {
            Ok(StreamRead::Bytes(bytes)) => {
                if stream == ProviderStream::Output {
                    frames.push(&bytes, &binding);
                }
            }
            Ok(StreamRead::Eof | StreamRead::Failed { .. }) => return,
            // Only this loop's own day-long idle bound re-arms the read; any
            // other failure ends the drain instead of spinning on it.
            Err(error) if matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(_)) => {}
            Err(_) => return,
        }
    }
}

fn copy(cx: &CallContext) -> CallContext {
    CallContext {
        generation: cx.generation,
        timeout: cx.timeout,
        cancellation: Arc::clone(&cx.cancellation),
    }
}

pub(super) fn within(cx: &CallContext, remaining: Duration) -> CallContext {
    CallContext {
        timeout: remaining.min(cx.timeout),
        ..copy(cx)
    }
}

pub(super) fn version_output(command: &Path, timeout: Duration) -> Result<String> {
    let mut child = std::process::Command::new(command)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| {
            se_core::scope::unreadable("Claude executable", &e.to_string()).with_cause(e)
        })?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                // Our own direct child, reaped below; never a name-matched kill.
                let _ = child.kill();
                let _ = child.wait();
                return Err(SeError::invalid(
                    "Claude version probe",
                    "an answer within the probe timeout",
                ));
            }
            Err(e) => {
                return Err(se_core::scope::unreadable(
                    "Claude version probe",
                    &e.to_string(),
                ));
            }
        }
    }
    let output = child
        .wait_with_output()
        .map_err(|e| se_core::scope::unreadable("Claude version probe", &e.to_string()))?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub(super) fn parse_version(text: &str) -> Option<(u16, u16, u16)> {
    let mut parts = text.split('.').map(|part| part.parse::<u16>().ok());
    Some((parts.next()??, parts.next()??, parts.next()??))
}

pub(super) fn poisoned() -> SeError {
    SeError::invalid(
        "Claude harness",
        "an unpoisoned probe cache; restart the host",
    )
}
