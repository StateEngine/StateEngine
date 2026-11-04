//! Stock Codex headless launch, one retained RPC connection, and exact-turn
//! interruption. The coordinator alone publishes activation and native exit.
mod channel;
mod location;
mod mail;
mod probe;
mod rpc;
mod state;
mod transport;
#[cfg(windows)]
mod windows_shell;
pub mod wire;
use super::codex_input::{self as input, CodexLaunch};
use crate::{
    BindingWitness, BlockingPool, CallContext, ConfigPlan, Harness, HarnessAttach, HarnessBinding,
    HarnessKind, HarnessRequest, HostFuture, LaunchOutcome, OwnedLaunchFile, ProbeRequest,
    ProviderInterrupt, ProviderInvocation, ProviderIoPlatform, ProviderStream, ProviderTransport,
    ProviderVersion, StreamRead,
};
use se_core::config_policy::{ConfigFile, Provider, ResolvedProfile};
use se_types::{NativePath, ProviderSessionId, Read, Result, SeError};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

pub struct CodexHarness {
    io: Arc<dyn ProviderIoPlatform>,
    pool: BlockingPool,
    state_home: PathBuf,
    #[cfg(unix)]
    socket_root: PathBuf,
    mcp_port: u16,
    configuration: ConfigFile,
    probed: Mutex<Option<ProviderVersion>>,
    #[cfg(windows)]
    windows_shell: Mutex<Option<PathBuf>>,
}
/// L1/L2 seam: one provider connection and a bounded, acknowledged queue of
/// actual completed item/turn notifications. No synthesized provider input.
pub struct Binding {
    io: Arc<dyn ProviderIoPlatform>,
    port: Arc<ProviderTransport>,
    sender: tokio::sync::Mutex<channel::Sender>,
    state: Mutex<state::State>,
    pub(crate) completion: state::Completion,
    rollout: Mutex<Option<NativePath>>,
    initial: tokio::sync::Mutex<Option<Value>>,
    input: tokio::sync::Mutex<()>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    diagnostic_secrets: Vec<se_types::Secret>,
}
impl CodexHarness {
    pub fn new(
        io: Arc<dyn ProviderIoPlatform>,
        pool: BlockingPool,
        state_home: PathBuf,
        socket_root: PathBuf,
        mcp_port: u16,
        configuration: ConfigFile,
    ) -> Self {
        #[cfg(not(unix))]
        let _ = socket_root;
        Self {
            io,
            pool,
            state_home,
            #[cfg(unix)]
            socket_root,
            mcp_port,
            configuration,
            probed: Mutex::new(None),
            #[cfg(windows)]
            windows_shell: Mutex::new(None),
        }
    }
    fn directory(&self, session: &se_types::SessionId) -> Result<PathBuf> {
        Ok(self.state_home.join("launch").join(
            se_proc::session_launch_id(session)
                .map_err(native_error)?
                .as_str(),
        ))
    }
    fn resolved(&self, request: &HarnessRequest) -> Result<ResolvedProfile> {
        self.configuration.resolve_profile(
            &request.profile.named_profile,
            Provider::Codex,
            request.mode == se_proc::LaunchMode::Headless,
        )
    }
    fn plan<'a>(
        &self,
        request: &'a HarnessRequest,
        resolved: &'a ResolvedProfile,
        socket: Option<&'a Path>,
    ) -> CodexLaunch<'a> {
        CodexLaunch {
            request,
            resolved,
            mcp_port: self.mcp_port,
            socket,
        }
    }
    pub(crate) async fn start_initial(
        &self,
        binding: &HarnessBinding,
        cx: CallContext,
    ) -> Result<()> {
        let binding = bound(binding)?;
        let params = binding.initial.lock().await.take().ok_or_else(|| {
            SeError::invalid(
                "Codex initial task",
                "the original unsent launch input; no duplicate turn/start",
            )
        })?;
        let result = binding.request("turn/start", params, &cx).await?;
        binding.accept_turn_response(&result)
    }
}
impl Binding {
    /// Provider-reported metadata only. L2 validates and pins the path under the
    /// existing CODEX_HOME before it grants file-read authority.
    pub fn rollout_path(&self) -> Result<Read<NativePath>> {
        Ok(self
            .rollout
            .lock()
            .map_err(|_| poisoned())?
            .clone()
            .map_or_else(
                || Read::Absent {
                    checked: "the bound app-server did not report a rollout path".into(),
                },
                |value| Read::Present { value },
            ))
    }
    fn accept_turn_response(&self, result: &Value) -> Result<()> {
        let id = result
            .pointer("/turn/id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= 512)
            .ok_or_else(|| {
                SeError::invalid("Codex turn/start response", "the actual bounded turn.id")
            })?;
        let mut state = self.state.lock().map_err(|_| poisoned())?;
        if !state.completed.iter().any(|done| done == id) {
            state.active_turn = Some(id.into());
        }
        Ok(())
    }
}
impl Harness for CodexHarness {
    fn kind(&self) -> HarnessKind {
        HarnessKind::CodexAppServer
    }
    fn probe<'a>(
        &'a self,
        request: ProbeRequest,
        cx: CallContext,
    ) -> HostFuture<'a, ProviderVersion> {
        Box::pin(async move {
            #[cfg(windows)]
            let until = std::time::Instant::now() + cx.timeout;
            let mut found = probe::probe(&request.command, cx.timeout).await?;
            #[cfg(windows)]
            {
                let environment = input::provider_environment();
                let deadline = crate::client::lease::Deadline::idle()?
                    .stage(until.saturating_duration_since(std::time::Instant::now()))?;
                let candidates = self
                    .pool
                    .run_owned(&deadline, move || windows_shell::candidates(&environment))
                    .await?;
                let mut selected = None;
                for shell in candidates {
                    if windows_shell::probe(
                        &shell,
                        &self.pool,
                        &context(
                            cx.generation,
                            until.saturating_duration_since(std::time::Instant::now()),
                        ),
                    )
                    .await?
                    {
                        selected = Some(shell);
                        break;
                    }
                }
                let shell = selected.ok_or_else(|| {
                    incompatible(
                        "no standard unpackaged PowerShell candidate qualifies",
                        "Install the PowerShell MSI and retry; the sandbox will not be widened.",
                    )
                })?;
                *self.windows_shell.lock().map_err(|_| poisoned())? = Some(shell);
            }
            found.protocol = if cfg!(unix) {
                "app-server/private-unix-websocket"
            } else {
                "app-server/stdio-json-lines"
            }
            .into();
            *self.probed.lock().map_err(|_| poisoned())? = Some(found.clone());
            Ok(found)
        })
    }
    fn configuration<'a>(
        &'a self,
        request: &'a HarnessRequest,
        _cx: CallContext,
    ) -> HostFuture<'a, ConfigPlan> {
        Box::pin(async move {
            let socket = self.socket(request)?;
            let resolved = self.resolved(request)?;
            input::thread(&self.plan(request, &resolved, socket.as_deref()))?;
            let plan = json!({"session":request.identity.session,"socket":socket.as_ref().map(|path| NativePath::from_local(path.clone())).transpose()?});
            let bytes = serde_json::to_vec(&plan)
                .map_err(|e| se_core::scope::unreadable("Codex launch plan", &e.to_string()))?;
            Ok(ConfigPlan {
                edits: vec![],
                ephemeral_files: vec![OwnedLaunchFile {
                    path: NativePath::from_local(
                        self.directory(&request.identity.session)?
                            .join("codex-plan.json"),
                    )?,
                    contents: se_types::Secret::new(bytes)?,
                }],
            })
        })
    }
    fn invocation<'a>(
        &'a self,
        request: &'a HarnessRequest,
        _cx: CallContext,
    ) -> HostFuture<'a, ProviderInvocation> {
        Box::pin(async move {
            let socket = self.socket(request)?;
            let resolved = self.resolved(request)?;
            let environment = input::provider_environment();
            #[cfg(windows)]
            let environment = windows_shell::apply(
                environment,
                self.windows_shell
                    .lock()
                    .map_err(|_| poisoned())?
                    .as_ref()
                    .ok_or_else(|| {
                        incompatible(
                            "unpackaged shell has not been probed",
                            "Probe the provider before launch.",
                        )
                    })?,
            )?;
            input::invocation(
                &self.plan(request, &resolved, socket.as_deref()),
                environment,
            )
        })
    }
    fn attach<'a>(
        &'a self,
        request: HarnessAttach,
        cx: CallContext,
    ) -> HostFuture<'a, LaunchOutcome> {
        Box::pin(async move {
            let until = std::time::Instant::now() + cx.timeout;
            let provider = self
                .probed
                .lock()
                .map_err(|_| poisoned())?
                .clone()
                .ok_or_else(|| {
                    SeError::invalid("Codex attach", "an actual successful executable probe")
                })?;
            let socket = self.socket(&request.request)?;
            let port = Arc::new(request.transport);
            let (sender, receiver) =
                channel::open(self.io.clone(), port.clone(), socket.as_deref(), &cx).await?;
            if let Some(socket) = &socket {
                let socket = socket.clone();
                let deadline = crate::client::lease::Deadline::idle()?
                    .stage(until.saturating_duration_since(std::time::Instant::now()))?;
                self.pool
                    .run_owned(&deadline, move || Self::validate_socket(&socket))
                    .await?;
            }
            let cx = context(
                cx.generation,
                until.saturating_duration_since(std::time::Instant::now()),
            );
            let binding = Arc::new(Binding {
                io: self.io.clone(),
                port: port.clone(),
                sender: tokio::sync::Mutex::new(sender),
                state: Mutex::new(state::State::default()),
                completion: Default::default(),
                rollout: Mutex::new(None),
                initial: tokio::sync::Mutex::new(None),
                input: tokio::sync::Mutex::new(()),
                tasks: Mutex::new(vec![]),
                diagnostic_secrets: vec![
                    se_types::Secret::new(request.request.mcp_bearer.expose().to_vec())?,
                    se_types::Secret::new(request.request.launch_credential.expose().to_vec())?,
                ],
            });
            let mut tasks = vec![
                tokio::spawn(rpc::read(Arc::downgrade(&binding), receiver, cx.generation)),
                tokio::spawn(channel::drain(
                    self.io.clone(),
                    port.clone(),
                    ProviderStream::Error,
                    cx.generation,
                )),
            ];
            if socket.is_some() {
                tasks.push(tokio::spawn(channel::drain(
                    self.io.clone(),
                    port,
                    ProviderStream::Output,
                    cx.generation,
                )));
            }
            *binding.tasks.lock().map_err(|_| poisoned())? = tasks;
            let handshake = tokio::time::timeout(cx.timeout, async {
                binding
                    .request("initialize", input::initialize(), &cx)
                    .await?;
                binding.notify("initialized", json!({}), &cx).await?;
                let resolved = self.resolved(&request.request)?;
                let plan = self.plan(&request.request, &resolved, socket.as_deref());
                let (method, params) = input::thread(&plan)?;
                let response = binding.request(method, params, &cx).await?;
                let conversation = input::verify_thread(&plan, &response)?;
                binding.state.lock().map_err(|_| poisoned())?.conversation =
                    Some(conversation.clone());
                if let Some(path) = response.pointer("/thread/path").and_then(Value::as_str) {
                    *binding.rollout.lock().map_err(|_| poisoned())? =
                        Some(NativePath::from_local(PathBuf::from(path))?);
                }
                let mut initial =
                    input::turn(&plan, &conversation, &request.request.initial_input)?;
                initial["clientUserMessageId"] = json!(format!(
                    "se-{}",
                    se_types::hex_lower(&Sha256::digest(request.request.key.as_str().as_bytes()))
                ));
                *binding.initial.lock().await = Some(initial);
                Ok::<_, SeError>(conversation)
            })
            .await
            .unwrap_or_else(|_| {
                Err(incompatible(
                    "provider handshake exceeded the original readiness deadline",
                    "Inspect the retained lifecycle and retry only after its cleanup.",
                ))
            });
            let conversation = match handshake {
                Ok(conversation) => conversation,
                Err(error) => {
                    let _ = close(&binding, &cx).await;
                    return Err(error);
                }
            };
            Ok(LaunchOutcome {
                witness: BindingWitness {
                    identity: request.request.identity,
                    conversation,
                    lifecycle: request.record.lifecycle,
                    provider,
                },
                binding: HarnessBinding {
                    claude: None,
                    codex: Some(binding),
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
            let binding = bound(binding)?;
            let conversation = binding.conversation()?;
            let active = binding.active_turn()?;
            if let Some(turn) = &active {
                binding
                    .request(
                        "turn/interrupt",
                        input::interrupt(&conversation, turn)?,
                        &cx,
                    )
                    .await?;
            }
            binding
                .sender
                .lock()
                .await
                .close(context(cx.generation, cx.timeout))
                .await?;
            Ok(ProviderInterrupt { conversation, requested: true, vendor_event: active.map_or_else(|| Read::Absent { checked: "no active vendor turn; native process exit remains independently required".into() }, |value| Read::Present { value }) })
        })
    }
    fn close_binding<'a>(
        &'a self,
        binding: &'a HarnessBinding,
        cx: CallContext,
    ) -> HostFuture<'a, ()> {
        Box::pin(async move { close(bound(binding)?, &cx).await })
    }
}
async fn close(binding: &Binding, cx: &CallContext) -> Result<()> {
    let tasks = std::mem::take(&mut *binding.tasks.lock().map_err(|_| poisoned())?);
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        if let Err(error) = task.await
            && !error.is_cancelled()
        {
            return Err(se_core::scope::unreadable(
                "Codex stream task",
                &error.to_string(),
            ));
        }
    }
    *binding.sender.lock().await = channel::Sender::Closed;
    binding
        .io
        .close(&binding.port, context(cx.generation, cx.timeout))
        .await
}
pub(crate) fn bound(binding: &HarnessBinding) -> Result<&Binding> {
    binding
        .codex
        .as_deref()
        .ok_or_else(|| SeError::invalid("provider binding", "the retained stock Codex binding"))
}
fn context(generation: se_types::Generation, timeout: Duration) -> CallContext {
    CallContext {
        generation,
        timeout,
        cancellation: Arc::new(crate::CancellationState { _private: () }),
    }
}
fn native_error(error: impl std::fmt::Display) -> SeError {
    se_core::scope::unreadable("Codex native custody", &error.to_string())
}
fn poisoned() -> SeError {
    se_core::scope::unreadable(
        "Codex binding",
        "retained state is poisoned; preserve custody and stop this lifecycle",
    )
}
pub(crate) fn incompatible(reason: &str, next_step: &str) -> SeError {
    SeError::new(se_types::Detail::ProviderIncompatible(
        se_types::details::ProviderIncompatible {
            subject: "Codex app-server".into(),
            reason: reason.into(),
            next_step: next_step.into(),
        },
    ))
}
