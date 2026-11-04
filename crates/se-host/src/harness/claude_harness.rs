//! The headless Claude `Harness` the launch coordinator drives (section 40
//! §9.1/§9.3, H09/H10). It plans files and argv through `super::claude`,
//! proves readiness from Claude's own init echo, and keeps both output pipes
//! drained for the provider's lifetime so a full pipe can never stall a turn.
//! Capture arrives through the pinned hook path; this harness reads nothing
//! a hook claims.
use super::claude::{self, ClaudeLaunch, Readiness};
mod attended;
mod completion;
mod io;
mod mail;
use crate::{
    BindingWitness, CallContext, ConfigPlan, Harness, HarnessAttach, HarnessBinding, HarnessKind,
    HarnessRequest, HostFuture, LaunchOutcome, ProbeRequest, ProviderInterrupt, ProviderInvocation,
    ProviderIoPlatform, ProviderStream, ProviderTransport, ProviderVersion, StreamRead,
};
use io::{drain, parse_version, poisoned, version_output, within, write_frame};
use se_types::{NativePath, ProviderSessionId, Read, Result, SeError};
use std::{
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
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
    pub(crate) attended: bool,
    io: Arc<dyn ProviderIoPlatform>,
    transport: ProviderTransport,
    conversation: ProviderSessionId,
    transcript: PathBuf,
    pub(crate) completion: completion::Completion,
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
            if request.request.mode == se_proc::LaunchMode::Window {
                return self.attach_attended(request, cx).await;
            }
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
                attended: false,
                io: Arc::clone(&self.io),
                transport: request.transport,
                conversation: conversation.clone(),
                transcript,
                completion: completion::Completion::default(),
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
                    if line.len() > completion::MAX_LINE {
                        return Err(SeError::too_large(
                            "Claude readiness frame",
                            completion::MAX_LINE,
                            line.len(),
                        ));
                    }
                    binding.completion.inspect(&line, &conversation);
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
            let readers = [ProviderStream::Output, ProviderStream::Error].map(|stream| {
                let initial = if stream == ProviderStream::Output {
                    std::mem::take(&mut pending)
                } else {
                    Vec::new()
                };
                tokio::spawn(drain(Arc::clone(&binding), stream, cx.generation, initial))
            });
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
                    codex: None,
                    _private: (),
                },
            })
        })
    }
    fn graceful_stop<'a>(
        &'a self,
        binding: &'a HarnessBinding,
        cx: CallContext,
    ) -> HostFuture<'a, ProviderInterrupt> {
        Box::pin(async move {
            let binding = claude_binding(binding)?;
            if binding.attended {
                return Ok(ProviderInterrupt { conversation: binding.conversation.clone(), requested: false,
                    vendor_event: Read::Absent { checked: "attended Claude owns its console; native scope stop supplies the exit witness".into() } });
            }
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
            if binding.attended {
                return Ok(());
            }
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
