//! Drain stderr while sending input and waiting for Claude's init echo.
//! Both futures stay inside attach; no startup task can outlive its owner.
use super::{
    Binding, READ_CHUNK,
    claude::{self, Readiness},
    completion,
    io::{within, write_frame},
};
use crate::{CallContext, ProviderStream, StreamRead};
use futures_util::future::{Either, select};
use se_types::{Body, Result, SeError};
use std::time::{Duration, Instant};

pub(super) async fn initialize(
    binding: &Binding,
    input: &Body,
    cx: &CallContext,
) -> Result<Vec<u8>> {
    let deadline = Instant::now() + cx.timeout;
    let readiness = async {
        write_frame(binding, input, &within(cx, remaining(deadline)?)).await?;
        let mut pending = Vec::new();
        loop {
            let remaining = remaining(deadline)?;
            let read = binding
                .io
                .read(
                    &binding.transport,
                    ProviderStream::Output,
                    READ_CHUNK,
                    within(cx, remaining),
                )
                .await?;
            let bytes = match read {
                StreamRead::Bytes(bytes) => bytes,
                StreamRead::Eof => {
                    return Err(SeError::invalid(
                        "Claude readiness",
                        "an init echo before the provider closed its output",
                    ));
                }
                StreamRead::Failed { error, .. } => return Err(SeError::from(error)),
            };
            pending.extend_from_slice(&bytes);
            let mut ready = false;
            while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
                let line: Vec<u8> = pending.drain(..=end).collect();
                if line.len() > completion::MAX_LINE {
                    return Err(SeError::too_large(
                        "Claude readiness frame",
                        completion::MAX_LINE,
                        line.len(),
                    ));
                }
                binding.completion.inspect(&line, &binding.conversation);
                match claude::readiness(&line, &binding.conversation) {
                    Readiness::Ready => ready = true,
                    Readiness::NotYet => (),
                    Readiness::Mismatch { echoed } => {
                        return Err(SeError::invalid(
                            "Claude conversation",
                            &format!("the selected conversation; the provider started {echoed}"),
                        ));
                    }
                }
            }
            if pending.len() > completion::MAX_LINE {
                return Err(SeError::too_large(
                    "Claude readiness frame",
                    completion::MAX_LINE,
                    pending.len(),
                ));
            }
            if ready {
                break;
            }
        }
        Ok::<_, SeError>(pending)
    };
    let errors = async {
        loop {
            match binding
                .io
                .read(
                    &binding.transport,
                    ProviderStream::Error,
                    READ_CHUNK,
                    within(cx, remaining(deadline)?),
                )
                .await?
            {
                StreamRead::Bytes(_) => (),
                StreamRead::Eof => return Ok::<_, SeError>(()),
                StreamRead::Failed { error, .. } => return Err(SeError::from(error)),
            }
        }
    };
    let readiness = std::pin::pin!(readiness);
    let errors = std::pin::pin!(errors);
    match select(readiness, errors).await {
        Either::Left((result, _)) => result,
        Either::Right((result, readiness)) => {
            result?;
            readiness.await
        }
    }
    // A cancelled Windows stderr read remains in its retained port and the
    // normal lifetime drain resumes it; failed startup keeps the binding for
    // the coordinator's exact native close/release.
}
fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| {
            SeError::invalid("Claude readiness", "an init echo within the launch timeout")
        })
}
