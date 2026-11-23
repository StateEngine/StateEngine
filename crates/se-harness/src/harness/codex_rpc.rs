//! Stock Codex headless launch, one retained RPC connection, and exact-turn
//! interruption. The coordinator alone publishes activation and native exit.
use crate::harness::binding::{AdapterBinding, Observation, StopPolicy};
mod attach;
mod channel;
mod connection;
#[cfg(target_os = "linux")]
mod console;
mod location;
mod mail;
pub mod probe;
mod qualification;
mod recovery;
mod rpc;
pub use rpc::RequestFailure;
#[cfg(feature = "remote")]
mod live;
mod state;
pub use state::IgnoredNotifications;
mod transport;
mod windows_sandbox;
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
use se_config::config_policy::{ConfigFile, Provider, ResolvedProfile};
use se_types::{NativePath, ProviderSessionId, Read, Result, SeError};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

/// What the login's shared app-server is started with.
pub struct ServerSettings {
    pub environment: Vec<(std::ffi::OsString, std::ffi::OsString)>,
    pub windows_sandbox: Option<&'static str>,
}

const LOGIN_RECORD: &str = "codex-login.json";

pub struct CodexHarness {
    io: Arc<dyn ProviderIoPlatform>,
    pool: BlockingPool,
    state_home: PathBuf,
    socket_root: PathBuf,
    mcp_port: u16,
    configuration: ConfigFile,
    atlas_helper: Option<(PathBuf, crate::AtlasHookConfigFn)>,
    /// This host's own executable, which runs as each agent's forwarder.
    forwarder: Option<PathBuf>,
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
    pub completion: state::Completion,
    rollout: Mutex<Option<NativePath>>,
    /// The Codex login recorded for this agent at launch.
    pub login: PathBuf,
    initial: tokio::sync::Mutex<Option<Value>>,
    input: tokio::sync::Mutex<()>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    attended: bool,
    #[cfg(feature = "remote")]
    pub live: std::sync::Mutex<Option<Arc<dyn crate::LivePublisher>>>,
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
        Self {
            io,
            pool,
            state_home,
            socket_root,
            mcp_port,
            configuration,
            atlas_helper: None,
            forwarder: None,
            probed: Mutex::new(None),
            #[cfg(windows)]
            windows_shell: Mutex::new(None),
        }
    }
    /// The environment and Windows sandbox selection the login's shared
    /// app-server starts with: what a private Codex process used to receive.
    pub fn server_settings(
        &self,
        request: &HarnessRequest,
        login: &Path,
    ) -> Result<ServerSettings> {
        let mut environment = input::provider_environment();
        // The login is given explicitly; the server never inherits the host's.
        environment.retain(|(name, _)| !name.eq_ignore_ascii_case("CODEX_HOME"));
        environment.push(("CODEX_HOME".into(), login.as_os_str().to_owned()));
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
        #[cfg(windows)]
        let windows_sandbox =
            windows_sandbox::selection(request, login)?.map(windows_sandbox::Implementation::key);
        #[cfg(not(windows))]
        let windows_sandbox = {
            let _ = request;
            None
        };
        Ok(ServerSettings {
            environment,
            windows_sandbox,
        })
    }
    /// The record of the login a launch chose, kept for the agent's whole life.
    pub fn login_record(
        &self,
        session: &se_types::SessionId,
        login: &Path,
    ) -> Result<OwnedLaunchFile> {
        let bytes = serde_json::to_vec(&json!({
            "session": session,
            "login": NativePath::from_local(login.to_owned())?,
        }))
        .map_err(|e| se_core::scope::unreadable("Codex login record", &e.to_string()))?;
        Ok(OwnedLaunchFile {
            path: NativePath::from_local(self.directory(session)?.join(LOGIN_RECORD))?,
            contents: se_types::Secret::new(bytes)?,
        })
    }
    /// The login recorded for this agent at launch: the one source of an
    /// agent's login after it starts.
    pub fn agent_login(&self, session: &se_types::SessionId) -> Result<Read<PathBuf>> {
        let path = self.directory(session)?.join(LOGIN_RECORD);
        let Some(mut file) = se_proc::OwnedFile::open(&path).map_err(native_error)? else {
            return Ok(Read::Absent {
                checked: format!("no Codex login is recorded at {}", path.display()),
            });
        };
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Recorded {
            session: se_types::SessionId,
            login: NativePath,
        }
        let recorded: Recorded = serde_json::from_slice(&file.read(8192).map_err(native_error)?)
            .map_err(|e| se_core::scope::unreadable("Codex login record", &e.to_string()))?;
        if &recorded.session != session {
            return Err(SeError::invalid(
                "Codex login record",
                "the exact recorded session",
            ));
        }
        Ok(Read::Present {
            value: recorded.login.to_local()?,
        })
    }
    /// Agents run as forwarders to their login's shared app-server.
    pub fn with_forwarder(mut self, executable: PathBuf) -> Self {
        self.forwarder = Some(executable);
        self
    }
    pub fn with_atlas_helper(
        mut self,
        executable: PathBuf,
        hook_config: crate::AtlasHookConfigFn,
    ) -> Self {
        if self.configuration.atlas.enabled && self.configuration.atlas.hooks {
            self.atlas_helper = Some((executable, hook_config));
        }
        self
    }
    fn thread(&self, launch: &CodexLaunch<'_>) -> Result<(&'static str, Value)> {
        let (method, mut params) = input::thread(launch)?;
        if let Some(hooks) = self
            .atlas_helper
            .as_ref()
            .and_then(|(image, build)| build(image, &self.state_home))
        {
            params["config"]["hooks"] = hooks;
            params["config"]["features.hooks"] = true.into();
        }
        Ok((method, params))
    }
    /// Ask the provider, once it is running in the sandbox this launch named,
    /// whether that implementation is ready for workspace-write.
    #[cfg(windows)]
    pub async fn confirm_windows_sandbox(
        &self,
        binding: &Binding,
        selection: Option<windows_sandbox::Implementation>,
        cx: &CallContext,
    ) -> Result<()> {
        let Some(implementation) = selection else {
            return Ok(());
        };
        // A provider without this method cannot answer whether it can hold
        // workspace-write, so the host must not claim it can.
        let answer = match binding
            .request_classified("windowsSandbox/readiness", Value::Null, cx)
            .await
        {
            Ok(answer) => answer,
            Err(failure) if failure.code == Some(-32601) => {
                return Err(incompatible(
                    "this Codex build cannot report its Windows sandbox readiness",
                    "Upgrade Codex to 0.152.0 or later, then retry the launch.",
                ));
            }
            Err(failure) => return Err(failure.error),
        };
        windows_sandbox::require_ready(
            implementation,
            windows_sandbox::Readiness::parse(&answer)?,
        )?;
        Ok(())
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
            request.mode.is_headless(),
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
}
impl Binding {
    /// A fresh persistent thread buffers its header until persistence is requested.
    /// Reading its empty history materializes it without executing user input.
    pub async fn materialize_fresh_rollout(&self, cx: &CallContext) -> Result<Option<SeError>> {
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
    fn recover<'a>(
        &'a self,
        request: crate::HarnessRecovery<'a>,
        cx: CallContext,
    ) -> HostFuture<'a, HarnessBinding> {
        Box::pin(async move {
            CodexHarness::recover(
                self,
                request.identity,
                request.conversation,
                request.transcript,
                request.attended,
                cx,
            )
            .await
        })
    }
    fn prepare<'a>(&'a self, request: &'a HarnessRequest, cx: CallContext) -> HostFuture<'a, ()> {
        Box::pin(async move { self.prepare_socket(request, &cx).await })
    }
    fn transcript_path(&self, binding: &HarnessBinding) -> Result<Option<PathBuf>> {
        let path = se_core::scope::require_present(
            bound(binding)?.rollout_path()?,
            "Codex rollout readiness",
            "Restore the exact provider-reported persistent thread path.",
        )?
        .to_local()?;
        crate::codex_capture::location(&path, &bound(binding)?.login).map(Some)
    }
    fn materialize_transcript<'a>(
        &'a self,
        binding: &'a HarnessBinding,
        cx: CallContext,
    ) -> HostFuture<'a, Option<SeError>> {
        Box::pin(async move { bound(binding)?.materialize_fresh_rollout(&cx).await })
    }
    fn transcript_validator(&self) -> crate::TranscriptValidator {
        crate::codex_capture::validate_header
    }
    fn kind(&self) -> HarnessKind {
        HarnessKind::CodexAppServer
    }
    fn probe<'a>(
        &'a self,
        request: ProbeRequest,
        cx: CallContext,
    ) -> HostFuture<'a, ProviderVersion> {
        Box::pin(self.qualify(request, cx, None))
    }
    fn probe_direct<'a>(
        &'a self,
        request: ProbeRequest,
        stamp: Option<se_proc::native_ipc::ExecutableStamp>,
        cx: CallContext,
    ) -> HostFuture<'a, ProviderVersion> {
        Box::pin(self.qualify(request, cx, stamp))
    }
    fn configuration<'a>(
        &'a self,
        request: &'a HarnessRequest,
        _cx: CallContext,
    ) -> HostFuture<'a, ConfigPlan> {
        Box::pin(async move {
            let socket = self.socket(request)?;
            let resolved = self.resolved(request)?;
            // The implementation is named in the launch settings, so the
            // request this preview builds carries no key of its own.
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
            // The host is the se executable, which also runs as each forwarder.
            let forwarder = match &self.forwarder {
                Some(path) => path.clone(),
                None => std::env::current_exe().map_err(|e| {
                    incompatible(
                        &format!("this host cannot name its own executable: {e}"),
                        "Restart StateEngine from its installed executable.",
                    )
                })?,
            };
            // The launch path appends the login's control socket, which only it
            // may choose.
            input::forwarder_invocation(
                &self.plan(request, &resolved, socket.as_deref()),
                &forwarder,
                environment,
            )
        })
    }
    fn attach<'a>(
        &'a self,
        request: HarnessAttach,
        _retained: &'a mut Option<HarnessBinding>,
        cx: CallContext,
    ) -> HostFuture<'a, LaunchOutcome> {
        Box::pin(async move {
            let mut timing = crate::startup_timing::Timing::new(&request.request.resume);
            self.attach_timed(request, cx, &mut timing).await
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
pub fn bound(binding: &HarnessBinding) -> Result<&Binding> {
    binding
        .get::<crate::codex_rpc::Binding>()
        .map(std::sync::Arc::as_ref)
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
pub fn incompatible(reason: &str, next_step: &str) -> SeError {
    SeError::new(se_types::Detail::ProviderIncompatible(
        se_types::details::ProviderIncompatible {
            subject: "Codex app-server".into(),
            reason: reason.into(),
            next_step: next_step.into(),
        },
    ))
}

impl AdapterBinding for Arc<Binding> {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn provider(&self) -> se_types::Provider {
        se_types::Provider::Codex
    }
    fn arm(&self, wake: &Arc<tokio::sync::Notify>) -> Result<()> {
        self.completion.arm(wake)
    }
    fn observe(&self, _capture: bool) -> Observation {
        let changed = self.completion.take();
        let mut observed = Observation {
            mail_pending: changed,
            capture_pending: changed,
            ..Default::default()
        };
        match self.active_turn() {
            Ok(turn) => observed.idle = Some(turn.is_none()),
            Err(error) => observed.failure = Some(error.body),
        }
        observed
    }
    fn stop_policy(&self) -> StopPolicy {
        // Closing the client transport leaves its persistent listener alive.
        // Signal only the host's exact owned native scope after protocol close.
        StopPolicy {
            #[cfg(target_os = "linux")]
            signal: Some(crate::harness::binding::Signal::Terminate),
            ..Default::default()
        }
    }
    fn start_initial(&self, cx: CallContext) -> HostFuture<'_, ()> {
        Box::pin(async move {
            let params = self.initial.lock().await.take().ok_or_else(|| {
                SeError::invalid(
                    "Codex initial task",
                    "the original unsent launch input; no duplicate turn/start",
                )
            })?;
            self.state
                .lock()
                .map_err(|_| poisoned())?
                .progress
                .offered();
            let result = self.request("turn/start", params, &cx).await?;
            self.accept_turn_response(&result)
        })
    }
}
