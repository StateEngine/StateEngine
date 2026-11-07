//! The headless Claude `Harness` the launch coordinator drives (section 40
//! §9.1/§9.3, H09/H10). It plans files and argv through `super::claude`,
//! proves readiness from Claude's own init echo, and keeps both output pipes
//! drained for the provider's lifetime so a full pipe can never stall a turn.
//! Capture arrives through the pinned hook path; this harness reads nothing
//! a hook claims.
use super::claude::{self, ClaudeLaunch};
mod attended;
mod completion;
mod io;
mod mail;
mod settings;
mod startup;
use crate::{
    BindingWitness, CallContext, ConfigPlan, Harness, HarnessAttach, HarnessBinding, HarnessKind,
    HarnessRequest, HostFuture, LaunchOutcome, ProbeRequest, ProviderInterrupt, ProviderInvocation,
    ProviderIoPlatform, ProviderStream, ProviderTransport, ProviderVersion,
};
use io::{drain, parse_version, poisoned, version_output};
use se_types::{NativePath, ProviderSessionId, Read, Result, SeError};
use std::{
    num::NonZeroU32,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
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
    bells: Option<Arc<crate::http::mail::bell::Bells>>,
    plugins: Mutex<std::collections::BTreeMap<se_types::SessionId, PathBuf>>,
    atlas_hooks: bool,
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
            bells: None,
            plugins: Mutex::default(),
            atlas_hooks: false,
        }
    }
    pub(crate) fn with_bells(mut self, bells: Arc<crate::http::mail::bell::Bells>) -> Self {
        self.bells = Some(bells);
        self
    }
    pub fn with_atlas_hooks(mut self, enabled: bool) -> Self {
        self.atlas_hooks = enabled;
        self
    }
    /// The protected per-launch directory the session pin also lives in.
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
    bell_session: se_types::SessionId,
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
        cx: CallContext,
    ) -> HostFuture<'a, ConfigPlan> {
        Box::pin(async move {
            let directory = self.launch_directory(request)?;
            let conversation = claude::conversation(request)?;
            let plan = self.plan(request, &directory, &conversation);
            let hooks = self
                .atlas_hooks
                .then(|| {
                    crate::atlas_hooks::hook_configuration(&self.se_executable, &self.state_home)
                })
                .flatten();
            let mut configuration = claude::configuration_with_hooks(&plan, hooks)?;
            if request.mode == se_proc::LaunchMode::Window
                && let Some(bells) = &self.bells
            {
                match claude::bell::configuration(&plan, bells) {
                    Ok((plugin, file)) => {
                        let command = request.executable.to_local()?;
                        let checked = plugin.clone();
                        let environment = claude::provider_environment();
                        let valid = tokio::task::spawn_blocking(move || {
                            io::plugin(&command, &checked, &environment, cx.timeout)
                        })
                        .await;
                        if matches!(valid, Ok(Ok(()))) {
                            self.plugins
                                .lock()
                                .map_err(|_| poisoned())?
                                .insert(request.identity.session.clone(), plugin);
                            configuration.ephemeral_files.push(file);
                        } else {
                            bells.retire(&request.identity.session)?;
                            configuration.ephemeral_files.push(claude::bell::unavailable(&directory, "The installed Claude Code refused the bundled mail mod; ask the agent to read its StateEngine inbox.")?);
                        }
                    }
                    Err(_) => {
                        bells.retire(&request.identity.session)?;
                        // A refused plugin never widens permissions or prevents
                        // an otherwise supported attended console from opening.
                        configuration.ephemeral_files.push(claude::bell::unavailable(&directory, "The bundled attended mail plugin could not be installed safely; ask the agent to read its StateEngine inbox.")?);
                    }
                }
            }
            Ok(configuration)
        })
    }
    fn invocation<'a>(
        &'a self,
        request: &'a HarnessRequest,
        cx: CallContext,
    ) -> HostFuture<'a, ProviderInvocation> {
        Box::pin(async move {
            let directory = self.launch_directory(request)?;
            let conversation = claude::conversation(request)?;
            let environment = claude::provider_environment();
            let command = request.executable.to_local()?;
            let auth_command = command.clone();
            let auth_environment = environment.clone();
            tokio::task::spawn_blocking(move || {
                io::authentication(&auth_command, &auth_environment, cx.timeout)
            })
            .await
            .map_err(|e| {
                se_core::scope::unreadable("Claude authentication status", &e.to_string())
            })??;
            let fallback = request.mode == se_proc::LaunchMode::Headless
                && request.profile.named_profile == "default"
                && !settings::has_saved_mode(
                    &command,
                    &request.cwd.to_local()?,
                    &environment,
                    cx.timeout,
                )
                .await?;
            let mut invocation =
                claude::invocation(&self.plan(request, &directory, &conversation), environment)?;
            if let Some(plugin) = self
                .plugins
                .lock()
                .map_err(|_| poisoned())?
                .get(&request.identity.session)
            {
                let at = invocation
                    .arguments
                    .iter()
                    .position(|a| a == "--")
                    .unwrap_or(invocation.arguments.len());
                invocation.arguments.splice(
                    at..at,
                    ["--plugin-dir".into(), plugin.as_os_str().to_owned()],
                );
            }
            if fallback {
                invocation
                    .arguments
                    .extend(["--permission-mode".into(), "acceptEdits".into()]);
            }
            Ok(invocation)
        })
    }
    fn attach<'a>(
        &'a self,
        request: HarnessAttach,
        retained: &'a mut Option<HarnessBinding>,
        cx: CallContext,
    ) -> HostFuture<'a, LaunchOutcome> {
        Box::pin(async move {
            if request.request.mode == se_proc::LaunchMode::Window {
                return self.attach_attended(request).await;
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
            let transcript = claude::transcript_location(
                &claude::config_home(&claude::provider_environment())?,
                &request.request,
                &conversation,
            )?;
            let binding = Arc::new(Binding {
                bell_session: request.request.identity.session.clone(),
                attended: false,
                io: Arc::clone(&self.io),
                transport: request.transport,
                conversation: conversation.clone(),
                transcript,
                completion: completion::Completion::default(),
                drains: Mutex::new(Vec::new()),
            });
            // Startup may leave pending Windows reads. Give the coordinator
            // custody before the first I/O so its normal failed-launch cleanup
            // can cancel/drain/release the exact port, including on a panic.
            *retained = Some(HarnessBinding {
                claude: Some(Arc::clone(&binding)),
                codex: None,
                _private: (),
            });
            let mut pending =
                startup::initialize(&binding, &request.request.initial_input, &cx).await?;
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
                if let Some(bells) = &self.bells {
                    bells.retire(&binding.bell_session)?;
                }
                self.plugins
                    .lock()
                    .map_err(|_| poisoned())?
                    .remove(&binding.bell_session);
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
