//! The headless Claude `Harness` the launch coordinator drives (section 40
//! §9.1/§9.3, H09/H10). It plans files and argv through `super::claude`,
//! proves readiness from Claude's own init echo, and keeps both output pipes
//! drained for the provider's lifetime so a full pipe can never stall a turn.
//! Capture arrives through the pinned hook path; this harness reads nothing
//! a hook claims.
use super::claude::{self, ClaudeLaunch, Readiness};
use crate::{
    BellOutcome, BindingWitness, BoundSession, CallContext, CaptureInput, ConfigPlan, Harness,
    HarnessAttach, HarnessBinding, HarnessKind, HarnessRequest, HostFuture, LaunchOutcome,
    OfferStage, OfferWitness, ProbeRequest, ProviderInterrupt, ProviderInvocation,
    ProviderIoPlatform, ProviderNotice, ProviderStream, ProviderTransport, ProviderVersion,
    StreamRead, TranscriptSource,
};
use se_types::{Body, NativePath, ProviderSessionId, Read, Result, SeError};
use std::{
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// The mods-capable floor section 40 §9.3 names; exact features are the
/// flags this harness passes, which the installed CLI must accept.
const MINIMUM_VERSION: (u16, u16, u16) = (2, 1, 287);
const READ_CHUNK: NonZeroU32 = match NonZeroU32::new(64 * 1024) {
    Some(value) => value,
    None => unreachable!(),
};

pub struct ClaudeHarness {
    io: Arc<dyn ProviderIoPlatform>,
    se_executable: PathBuf,
    state_home: PathBuf,
    mcp_port: u16,
    probed: Mutex<Option<ProviderVersion>>,
}
impl ClaudeHarness {
    /// `se_executable` is the trusted installed se the hooks call; `mcp_port`
    /// is this host's bound loopback MCP port.
    pub fn new(
        io: Arc<dyn ProviderIoPlatform>,
        se_executable: PathBuf,
        state_home: PathBuf,
        mcp_port: u16,
    ) -> Self {
        Self {
            io,
            se_executable,
            state_home,
            mcp_port,
            probed: Mutex::new(None),
        }
    }
    /// The protected per-launch directory 5p's session pin also lives in.
    pub fn launch_directory(&self, request: &HarnessRequest) -> Result<PathBuf> {
        Ok(self
            .state_home
            .join("launch")
            .join(format!("lch_{}", claude::session_uuid(request)?)))
    }
    fn plan<'a>(
        &'a self,
        request: &'a HarnessRequest,
        directory: &'a Path,
        conversation: &'a ProviderSessionId,
    ) -> ClaudeLaunch<'a> {
        ClaudeLaunch {
            request,
            se_executable: &self.se_executable,
            state_home: &self.state_home,
            launch_directory: directory,
            mcp_port: self.mcp_port,
            conversation,
            resume: matches!(request.resume, Read::Present { .. }),
        }
    }
}

/// Retained for the provider's lifetime: host stream ends and the drain.
pub(crate) struct Binding {
    io: Arc<dyn ProviderIoPlatform>,
    transport: ProviderTransport,
    conversation: ProviderSessionId,
    transcript: PathBuf,
    /// The output/error readers, joined by close_binding.
    drains: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl Harness for ClaudeHarness {
    fn kind(&self) -> HarnessKind {
        HarnessKind::ClaudeCode
    }
    fn probe<'a>(
        &'a self,
        request: ProbeRequest,
        cx: CallContext,
    ) -> HostFuture<'a, ProviderVersion> {
        Box::pin(async move {
            let command = request.command.clone();
            let timeout = cx.timeout;
            let output = tokio::task::spawn_blocking(move || version_output(&command, timeout))
                .await
                .map_err(|e| {
                    se_core::scope::unreadable("Claude version probe", &e.to_string())
                })??;
            let version = output
                .split_whitespace()
                .next()
                .filter(|_| output.contains("Claude Code"))
                .ok_or_else(|| {
                    SeError::invalid("Claude version", "`<version> (Claude Code)` output")
                })?
                .to_owned();
            if parse_version(&version).is_none_or(|found| found < MINIMUM_VERSION) {
                return Err(SeError::invalid(
                    "Claude version",
                    "Claude Code 2.1.287 or newer; update Claude Code and retry",
                ));
            }
            let probed = ProviderVersion {
                kind: HarnessKind::ClaudeCode,
                executable: NativePath::from_local(request.command)?,
                version,
                protocol: "stream-json".into(),
            };
            *self.probed.lock().map_err(|_| poisoned())? = Some(probed.clone());
            Ok(probed)
        })
    }
    fn configuration<'a>(
        &'a self,
        request: &'a HarnessRequest,
        _cx: CallContext,
    ) -> HostFuture<'a, ConfigPlan> {
        Box::pin(async move {
            let directory = self.launch_directory(request)?;
            let conversation = claude::conversation(request)?;
            claude::configuration(&self.plan(request, &directory, &conversation))
        })
    }
    fn invocation<'a>(
        &'a self,
        request: &'a HarnessRequest,
        _cx: CallContext,
    ) -> HostFuture<'a, ProviderInvocation> {
        Box::pin(async move {
            let directory = self.launch_directory(request)?;
            let conversation = claude::conversation(request)?;
            claude::invocation(
                &self.plan(request, &directory, &conversation),
                claude::provider_environment(),
            )
        })
    }
    fn attach<'a>(
        &'a self,
        request: HarnessAttach,
        cx: CallContext,
    ) -> HostFuture<'a, LaunchOutcome> {
        Box::pin(async move {
            let provider = self
                .probed
                .lock()
                .map_err(|_| poisoned())?
                .clone()
                .ok_or_else(|| {
                    SeError::invalid("Claude launch", "a provider probe before attach")
                })?;
            let conversation = claude::conversation(&request.request)?;
            let transcript = claude::transcript_path(
                &claude::config_home(&claude::provider_environment())?,
                &request.request.cwd.to_local()?,
                &conversation,
            );
            let binding = Arc::new(Binding {
                io: Arc::clone(&self.io),
                transport: request.transport,
                conversation: conversation.clone(),
                transcript,
                drains: Mutex::new(Vec::new()),
            });
            // Deliver the task, then require Claude's own echo of the exact
            // selected conversation; prepared argv is not readiness.
            write_frame(&binding, &request.request.initial_input, &cx).await?;
            let deadline = Instant::now() + cx.timeout;
            let mut pending = Vec::new();
            loop {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .filter(|left| !left.is_zero())
                    .ok_or_else(|| {
                        SeError::invalid(
                            "Claude readiness",
                            "an init echo within the launch timeout",
                        )
                    })?;
                let read = binding
                    .io
                    .read(
                        &binding.transport,
                        ProviderStream::Output,
                        READ_CHUNK,
                        within(&cx, remaining),
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
                    match claude::readiness(&line, &conversation) {
                        Readiness::Ready => ready = true,
                        Readiness::NotYet => (),
                        Readiness::Mismatch { echoed } => {
                            return Err(SeError::invalid(
                                "Claude conversation",
                                &format!(
                                    "the selected conversation; the provider started {echoed}"
                                ),
                            ));
                        }
                    }
                }
                if ready {
                    break;
                }
            }
            let readers = [ProviderStream::Output, ProviderStream::Error]
                .map(|stream| tokio::spawn(drain(Arc::clone(&binding), stream, cx.generation)));
            binding
                .drains
                .lock()
                .map_err(|_| poisoned())?
                .extend(readers);
            Ok(LaunchOutcome {
                witness: BindingWitness {
                    identity: request.request.identity.clone(),
                    conversation,
                    lifecycle: request.record.lifecycle.clone(),
                    provider,
                },
                binding: HarnessBinding {
                    claude: Some(binding),
                    _private: (),
                },
            })
        })
    }
    fn adopt<'a>(
        &'a self,
        _witness: BindingWitness,
        _cx: CallContext,
    ) -> HostFuture<'a, Read<HarnessBinding>> {
        Box::pin(async move {
            Ok(Read::Unknown {
                what: "re-adopting a running headless Claude after handover is not implemented"
                    .into(),
            })
        })
    }
    fn bell<'a>(
        &'a self,
        binding: &'a HarnessBinding,
        notice: &'a ProviderNotice,
        cx: CallContext,
    ) -> HostFuture<'a, BellOutcome> {
        Box::pin(async move {
            let binding = claude_binding(binding)?;
            // IDs only: the agent reads bodies through its own MCP tools.
            let ids: Vec<&str> = notice.messages.iter().map(|id| id.as_str()).collect();
            let text = format!(
                "New StateEngine mail for you: {}. Read it with the stateengine_msg_list tool and act on it.",
                ids.join(", ")
            );
            write_frame(binding, &Body::new(text)?, &cx).await?;
            Ok(BellOutcome::Offered(OfferWitness {
                notice: notice.id.clone(),
                identity: notice.identity.clone(),
                conversation: binding.conversation.clone(),
                digest: notice.digest,
                stage: OfferStage::TransportWritten,
                vendor_event: Read::Absent {
                    checked: "headless Claude acknowledges input only by starting its next turn"
                        .into(),
                },
            }))
        })
    }
    fn transcript<'a>(
        &'a self,
        binding: &'a HarnessBinding,
        _cx: CallContext,
    ) -> HostFuture<'a, Read<TranscriptSource>> {
        Box::pin(async move {
            let binding = claude_binding(binding)?;
            // The location only. The capture pin, not this path, authorizes reads,
            // and the file's identity is taken when it is pinned.
            Ok(Read::Unknown {
                what: format!(
                    "{} is pinned by the trusted capture bind, not reported here",
                    binding.transcript.display()
                ),
            })
        })
    }
    fn capture<'a>(
        &'a self,
        _session: &'a BoundSession,
        _input: CaptureInput,
        _cx: CallContext,
    ) -> HostFuture<'a, se_types::Receipt<se_types::EventId>> {
        Box::pin(async move {
            Err(SeError::invalid(
                "Claude capture",
                "the pinned-source hook path; headless output is activity, not turns",
            ))
        })
    }
    fn graceful_stop<'a>(
        &'a self,
        binding: &'a HarnessBinding,
        cx: CallContext,
    ) -> HostFuture<'a, ProviderInterrupt> {
        Box::pin(async move {
            let binding = claude_binding(binding)?;
            // Closing stdin ends a headless session after its current turn.
            binding.io.finish_input(&binding.transport, cx).await?;
            Ok(ProviderInterrupt {
                conversation: binding.conversation.clone(),
                requested: true,
                vendor_event: Read::Absent {
                    checked: "headless Claude reports no interrupt event; exit is witnessed by the coordinator".into(),
                },
            })
        })
    }
    fn close_binding<'a>(
        &'a self,
        binding: &'a HarnessBinding,
        cx: CallContext,
    ) -> HostFuture<'a, ()> {
        Box::pin(async move {
            let binding = claude_binding(binding)?;
            // A reader holds its stream across a pending read, so stop every
            // reader before releasing the streams they hold. Both steps are
            // repeatable: a retry finds no readers and closes what is left.
            let readers = std::mem::take(&mut *binding.drains.lock().map_err(|_| poisoned())?);
            for reader in &readers {
                reader.abort();
            }
            let mut failed = None;
            for reader in readers {
                match reader.await {
                    Ok(()) => {}
                    Err(joined) if joined.is_cancelled() => {}
                    Err(joined) => {
                        failed.get_or_insert_with(|| {
                            se_core::scope::unreadable(
                                "provider stream reader",
                                &joined.to_string(),
                            )
                        });
                    }
                }
            }
            binding.io.close(&binding.transport, cx).await?;
            failed.map_or(Ok(()), Err)
        })
    }
}

/// The transcript Claude writes for this binding, for the capture bind.
pub fn transcript_location(binding: &HarnessBinding) -> Result<PathBuf> {
    Ok(claude_binding(binding)?.transcript.clone())
}

fn claude_binding(binding: &HarnessBinding) -> Result<&Binding> {
    binding
        .claude
        .as_deref()
        .ok_or_else(|| SeError::invalid("provider binding", "a headless Claude binding"))
}

async fn write_frame(binding: &Binding, body: &Body, cx: &CallContext) -> Result<()> {
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
async fn drain(binding: Arc<Binding>, stream: ProviderStream, generation: se_types::Generation) {
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
            Ok(StreamRead::Bytes(_)) => (),
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

fn within(cx: &CallContext, remaining: Duration) -> CallContext {
    CallContext {
        timeout: remaining.min(cx.timeout),
        ..copy(cx)
    }
}

fn version_output(command: &Path, timeout: Duration) -> Result<String> {
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

fn parse_version(text: &str) -> Option<(u16, u16, u16)> {
    let mut parts = text.split('.').map(|part| part.parse::<u16>().ok());
    Some((parts.next()??, parts.next()??, parts.next()??))
}

fn poisoned() -> SeError {
    SeError::invalid(
        "Claude harness",
        "an unpoisoned probe cache; restart the host",
    )
}
