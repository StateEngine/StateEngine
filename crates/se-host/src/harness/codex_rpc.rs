//! Stock Codex headless launch, one retained RPC connection, and exact-turn
//! interruption. The coordinator alone publishes activation and native exit.
mod attach;
mod channel;
mod connection;
#[cfg(target_os = "linux")]
mod console;
mod location;
mod mail;
mod probe;
mod qualification;
mod recovery;
mod rpc;
pub use rpc::RequestFailure;
mod state;
pub use state::IgnoredNotifications;
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
    atlas_helper: Option<PathBuf>,
    probed: Mutex<Option<qualification::Qualified>>,
    #[cfg(windows)]
    windows_shell: Mutex<Option<PathBuf>>,
}
/// L1/L2 seam: one provider connection and a bounded, acknowledged queue of
/// actual completed item/turn notifications. No synthesized provider input.
pub struct Binding {
    io: Arc<dyn ProviderIoPlatform>,
    port: Option<Arc<ProviderTransport>>,
    sender: tokio::sync::Mutex<channel::Sender>,
    state: Mutex<state::State>,
    pub(crate) completion: state::Completion,
    rollout: Mutex<Option<NativePath>>,
    initial: tokio::sync::Mutex<Option<Value>>,
    input: tokio::sync::Mutex<()>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    attended: bool,
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
            atlas_helper: None,
            probed: Mutex::new(None),
            #[cfg(windows)]
            windows_shell: Mutex::new(None),
        }
    }
    pub fn with_atlas_helper(mut self, executable: PathBuf) -> Self {
        if self.configuration.atlas.enabled && self.configuration.atlas.hooks {
            self.atlas_helper = Some(executable);
        }
        self
    }
    fn thread(&self, launch: &CodexLaunch<'_>) -> Result<(&'static str, Value)> {
        let (method, mut params) = input::thread(launch)?;
        if let Some(hooks) = self
            .atlas_helper
            .as_ref()
            .and_then(|image| crate::atlas_hooks::hook_configuration(image, &self.state_home))
        {
            params["config"]["hooks"] = hooks;
            params["config"]["features.hooks"] = true.into();
        }
        Ok((method, params))
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
    /// A fresh persistent thread buffers its header until persistence is requested.
    /// Reading its empty history materializes it without executing user input.
    pub(crate) async fn materialize_fresh_rollout(
        &self,
        cx: &CallContext,
    ) -> Result<Option<SeError>> {
        let conversation = self.conversation()?;
        let response = match self
            .request_classified(
                "thread/read",
                json!({"threadId":conversation.as_str(),"includeTurns":true}),
                cx,
            )
            .await
        {
            Ok(response) => response,
            // Stock 0.163 persists the fresh header, then its unsupported
            // history listing refuses. Preserve that diagnostic; the caller
            // must independently pin and validate the native header before C3.
            Err(failure) if failure.code == Some(-32601) => {
                return Ok(Some(failure.error));
            }
            Err(failure) => return Err(failure.error),
        };
        let thread = response.get("thread").ok_or_else(|| {
            incompatible(
                "empty thread read omitted its thread",
                "Restore native rollout readiness.",
            )
        })?;
        if thread.get("id").and_then(Value::as_str) != Some(conversation.as_str())
            || thread
                .get("turns")
                .and_then(Value::as_array)
                .is_none_or(|turns| !turns.is_empty())
        {
            return Err(incompatible(
                "fresh rollout read returned another thread or nonempty history",
                "Inspect the exact native thread; no task was submitted.",
            ));
        }
        let path = thread.get("path").and_then(Value::as_str).ok_or_else(|| {
            incompatible(
                "empty thread read omitted its persistent path",
                "Restore native rollout readiness.",
            )
        })?;
        if !matches!(self.rollout_path()?, Read::Present { value } if value.to_local().ok().as_deref() == Some(Path::new(path)))
        {
            return Err(incompatible(
                "fresh rollout read changed its persistent path",
                "Inspect the exact native thread; no task was submitted.",
            ));
        }
        Ok(None)
    }
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
        Box::pin(self.qualify(request, cx, false))
    }
    fn probe_direct<'a>(
        &'a self,
        request: ProbeRequest,
        cx: CallContext,
    ) -> HostFuture<'a, ProviderVersion> {
        Box::pin(self.qualify(request, cx, true))
    }
    fn configuration<'a>(
        &'a self,
        request: &'a HarnessRequest,
        _cx: CallContext,
    ) -> HostFuture<'a, ConfigPlan> {
        Box::pin(async move {
            let socket = self.socket(request)?;
            let resolved = self.resolved(request)?;
            self.thread(&self.plan(request, &resolved, socket.as_deref()))?;
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
            let mut invocation = input::invocation(
                &self.plan(request, &resolved, socket.as_deref()),
                environment,
            )?;
            if self.atlas_helper.is_some() {
                invocation.environment.entries.push((
                    "SE_SESSION".into(),
                    request.identity.session.as_str().into(),
                ));
            }
            Ok(invocation)
        })
    }
    fn attach<'a>(
        &'a self,
        request: HarnessAttach,
        _retained: &'a mut Option<HarnessBinding>,
        cx: CallContext,
    ) -> HostFuture<'a, LaunchOutcome> {
        Box::pin(async move {
            self.attach_transport(
                &request.request,
                request.transport,
                request.record.lifecycle,
                cx,
            )
            .await
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
    if let Some(port) = &binding.port {
        binding
            .io
            .close(port, context(cx.generation, cx.timeout))
            .await?;
    }
    Ok(())
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
