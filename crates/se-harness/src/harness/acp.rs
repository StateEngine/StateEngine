//! Configured ACP executables use the same native launch lifecycle as stock harnesses.
use super::*;
use crate::acp::{CapturedMessage, Connection, PermissionPolicy, Session, WorkspaceAccess};
use crate::harness::binding::{AdapterBinding, Observation, StopPolicy};
use se_config::config_policy::{ConfigFile, Provider, ResolvedProfile};
use se_types::{Result, SeError};
use serde_json::json;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
mod capture;
mod environment;
mod mail;

pub struct AcpHarness {
    io: Arc<dyn ProviderIoPlatform>,
    configuration: ConfigFile,
    se_executable: std::path::PathBuf,
    home: std::path::PathBuf,
    mcp_port: u16,
}
pub struct Binding {
    pub session: Arc<Session>,
    pub identity: SessionIdentity,
    initial: Mutex<Option<(String, String)>>,
    incarnation: Mutex<Option<Vec<u8>>>,
    capture_offset: AtomicU64,
    interrupted_captured: AtomicBool,
    interrupted_prefix: Mutex<Option<(String, String)>>,
    cwd: String,
}
impl Binding {
    pub fn runtime_view(&self) -> Result<se_core::ops::AcpRuntimeView> {
        let observed = self.session.observe()?;
        let phase_started_at = observed.phase_started.and_then(|at| {
            let wall = std::time::SystemTime::now().checked_sub(at.elapsed())?;
            let micros = wall.duration_since(std::time::UNIX_EPOCH).ok()?.as_micros();
            se_types::format_timestamp(i64::try_from(micros).ok()?).ok()
        });
        Ok(se_core::ops::AcpRuntimeView {
            activity: if observed.failure.is_some() {
                "failed"
            } else if observed.cancelling {
                "cancelling"
            } else if observed.active_input.is_some() {
                "working"
            } else {
                "idle"
            }
            .into(),
            phase_started_at,
            phase_seconds: observed.phase_started.map(|at| at.elapsed().as_secs()),
            mode: observed.current_mode,
            last_permission_refusal: observed.permission_refusal.map(|v| v.reason.into()),
            provisional_reply: observed
                .provisional_text
                .map(|v| se_core::ops::AcpReplyPreview {
                    text: v.text,
                    total_bytes: v.total_bytes,
                    omitted_bytes: v.omitted_bytes,
                }),
            failure: observed.failure,
        })
    }
}
impl Binding {
    /// The context usage the protocol agent last reported for this session.
    pub fn context(
        &self,
        configured: Option<u64>,
    ) -> Result<se_types::Read<se_core::ops::ContextWindowView>> {
        let usage = self.session.context()?;
        Ok(super::context_usage::view(
            usage,
            configured,
            "The protocol agent",
        ))
    }
}
fn error(reason: impl std::fmt::Display) -> SeError {
    se_core::scope::unreadable("ACP binding", &reason.to_string())
}
impl AcpHarness {
    pub fn new(
        io: Arc<dyn ProviderIoPlatform>,
        configuration: ConfigFile,
        se_executable: std::path::PathBuf,
        home: std::path::PathBuf,
        mcp_port: u16,
    ) -> Self {
        Self {
            io,
            configuration,
            se_executable,
            home,
            mcp_port,
        }
    }
    fn resolved(&self, request: &HarnessRequest) -> Result<ResolvedProfile> {
        Self::validate_launch(
            &self.configuration,
            &request.profile.named_profile,
            request.profile.model.as_deref(),
            request.profile.harness.as_deref(),
        )
    }
    pub fn validate_launch(
        configuration: &ConfigFile,
        named_profile: &str,
        model: Option<&str>,
        harness: Option<&str>,
    ) -> Result<ResolvedProfile> {
        let profile = configuration.resolve_profile(named_profile, Provider::Acp, true)?;
        let settings = configuration.acp_settings(harness, named_profile)?;
        let argument_model = settings.arguments.iter().any(|v| v.contains("{model}"));
        if argument_model && model.is_none() {
            return Err(error(
                "The selected harness's model binding requires a saved model. Select a model for this agent, or remove that binding to use the native harness default.",
            ));
        }
        Ok(profile)
    }
    fn attach_servers(
        &self,
        request: &HarnessRequest,
        http_mcp: bool,
    ) -> Result<Vec<serde_json::Value>> {
        if http_mcp && self.mcp_port != 0 {
            let bearer = std::str::from_utf8(request.mcp_bearer.expose())
                .map_err(|_| error("MCP bearer is not UTF-8"))?;
            let proof = std::str::from_utf8(request.launch_credential.expose())
                .map_err(|_| error("session proof is not UTF-8"))?;
            return Ok(vec![json!({
                "type": "http",
                "name": "stateengine",
                "url": format!("http://127.0.0.1:{}/mcp", self.mcp_port),
                "headers": [
                    {"name": "Authorization", "value": format!("Bearer {bearer}")},
                    {"name": "X-StateEngine-Session-Proof", "value": proof}
                ]
            })]);
        }
        let command = self
            .se_executable
            .to_str()
            .ok_or_else(|| error("the StateEngine executable path is not valid UTF-8"))?;
        let home = self
            .home
            .to_str()
            .ok_or_else(|| error("the state home path is not valid UTF-8"))?;
        Ok(vec![json!({
            "name": "stateengine",
            "command": command,
            "args": ["mcp", "--stdio"],
            "env": [
                {"name": "SE_SESSION", "value": request.identity.session.as_str()},
                {"name": "SE_HOME", "value": home}
            ]
        })])
    }
    async fn open_conversation(
        &self,
        session: &Session,
        request: &HarnessRequest,
        settings: &se_config::config_policy::harness::InvocationSettings,
        remaining: &impl Fn() -> CallContext,
    ) -> Result<String> {
        let http_mcp = session.supports_http_mcp(settings.unadvertised_http_mcp)?;
        let servers = self.attach_servers(request, http_mcp)?;
        let replay = attach_replay(request)?;
        let cwd = request.cwd.to_local()?;
        let cwd = cwd
            .to_str()
            .ok_or_else(|| error("protocol cwd is not UTF-8"))?;
        let conversation = session
            .open(
                cwd,
                servers,
                replay,
                &settings.mode,
                settings.unadvertised_http_mcp,
                remaining(),
            )
            .await?;
        let cli_or_env_model = settings.arguments.iter().any(|v| v.contains("{model}"))
            || settings
                .model_arguments
                .iter()
                .any(|v| v.contains("{model}"))
            || settings.model_environment.is_some();
        if let Some(model) = request.profile.model.as_deref()
            && !cli_or_env_model
        {
            session.set_model(model, remaining()).await?;
        }
        Ok(conversation)
    }
}
pub fn bound(binding: &HarnessBinding) -> Result<&Arc<Binding>> {
    binding
        .get::<crate::harness::acp::Binding>()
        .ok_or_else(|| error("the original protocol binding is absent"))
}
impl Harness for AcpHarness {
    fn canonical_resume(&self) -> bool {
        true
    }
    fn transcript_path(&self, _binding: &HarnessBinding) -> Result<Option<std::path::PathBuf>> {
        Ok(None)
    }
    fn kind(&self) -> HarnessKind {
        HarnessKind::Acp
    }
    fn probe<'a>(
        &'a self,
        request: ProbeRequest,
        _cx: CallContext,
    ) -> HostFuture<'a, ProviderVersion> {
        Box::pin(async move {
            if request.kind != HarnessKind::Acp || !request.command.is_absolute() {
                return Err(error("the configured absolute executable is required"));
            }
            // The actual in-custody initialize exchange qualifies the protocol before input.
            Ok(ProviderVersion {
                kind: HarnessKind::Acp,
                executable: NativePath::from_local(request.command)?,
                version: "executable version not queried".into(),
                protocol: "ACP v1 required".into(),
            })
        })
    }
    fn configuration<'a>(
        &'a self,
        request: &'a HarnessRequest,
        _cx: CallContext,
    ) -> HostFuture<'a, ConfigPlan> {
        Box::pin(async move {
            self.resolved(request)?;
            Ok(ConfigPlan {
                edits: Vec::new(),
                ephemeral_files: Vec::new(),
            })
        })
    }
    fn invocation<'a>(
        &'a self,
        request: &'a HarnessRequest,
        _cx: CallContext,
    ) -> HostFuture<'a, ProviderInvocation> {
        Box::pin(async move {
            self.resolved(request)?;
            let settings = self.configuration.acp_settings(
                request.profile.harness.as_deref(),
                &request.profile.named_profile,
            )?;
            let model = request.profile.model.as_deref();
            let mut arguments = settings.arguments;
            if model.is_some() {
                arguments.extend(settings.model_arguments);
            }
            let arguments = arguments
                .iter()
                .map(|v| v.replace("{model}", model.unwrap_or_default()).into())
                .collect();
            let mut environment = environment::inherited();
            // Provider-specific account/configuration stays with the provider. Forward only
            // the additional names explicitly selected by the human configuration.
            for key in &settings.environment {
                if let Some(value) = std::env::var_os(key) {
                    environment
                        .retain(|(name, _)| !name.to_string_lossy().eq_ignore_ascii_case(key));
                    environment.push((key.into(), value));
                }
            }
            for (key, value) in &settings.values {
                environment.retain(|(name, _)| !name.to_string_lossy().eq_ignore_ascii_case(key));
                environment.push((key.into(), value.into()));
            }
            if let (Some(key), Some(model)) = (&settings.model_environment, model) {
                environment.retain(|(name, _)| !name.to_string_lossy().eq_ignore_ascii_case(key));
                environment.push((key.into(), model.into()));
            }
            environment
                .retain(|(name, _)| !name.to_string_lossy().eq_ignore_ascii_case("SE_SESSION"));
            // The ACP child and its subprocesses see only the public handle;
            // se resolves the secret from the owner-only launch pin.
            environment.push((
                "SE_SESSION".into(),
                request.identity.session.as_str().into(),
            ));
            environment.retain(|(name, _)| !name.to_string_lossy().eq_ignore_ascii_case("SE_HOME"));
            environment.push(("SE_HOME".into(), self.home.as_os_str().to_owned()));
            Ok(ProviderInvocation {
                executable: request.executable.clone(),
                arguments,
                environment: se_proc::Environment {
                    entries: environment,
                },
            })
        })
    }
    fn attach<'a>(
        &'a self,
        attach: HarnessAttach,
        retained: &'a mut Option<HarnessBinding>,
        cx: CallContext,
    ) -> HostFuture<'a, LaunchOutcome> {
        Box::pin(async move {
            let request = attach.request;
            let resolved = self.resolved(&request)?;
            let (connection, incoming) =
                Connection::open(self.io.clone(), attach.transport, cx.generation).await;
            let policy = PermissionPolicy::from_saved_approval(resolved.approval);
            let allow_terminal = matches!(
                (resolved.sandbox, policy),
                (
                    se_config::config_policy::EffectiveSandbox::Bypass,
                    PermissionPolicy::NeverAsk
                )
            );
            let session = Session::retain_with_capabilities(
                connection,
                incoming,
                PermissionPolicy::from_saved_approval(resolved.approval),
                WorkspaceAccess::from_saved_sandbox(resolved.sandbox),
                attach.provider_exit,
            )
            .await;
            let binding = Arc::new(Binding {
                session,
                identity: request.identity.clone(),
                initial: Mutex::new(Some((
                    request.key.as_str().into(),
                    crate::harness::with_atlas_guidance(
                        self.configuration.atlas.enabled,
                        request.initial_input.as_str(),
                    ),
                ))),
                incarnation: Mutex::new(None),
                capture_offset: AtomicU64::new(0),
                interrupted_captured: AtomicBool::new(false),
                interrupted_prefix: Mutex::new(None),
                cwd: request
                    .cwd
                    .to_local()?
                    .to_str()
                    .ok_or_else(|| error("protocol cwd is not UTF-8"))?
                    .into(),
            });
            let wrap = || HarnessBinding::new(binding.clone());
            *retained = Some(wrap());
            let until = tokio::time::Instant::now() + cx.timeout;
            let remaining = || CallContext {
                generation: cx.generation,
                timeout: until.saturating_duration_since(tokio::time::Instant::now()),
                cancellation: cx.cancellation.clone(),
            };
            binding.session.initialize(remaining()).await?;
            let settings = self.configuration.acp_settings(
                request.profile.harness.as_deref(),
                &request.profile.named_profile,
            )?;
            let conversation = self
                .open_conversation(&binding.session, &request, &settings, &remaining)
                .await?;
            let conversation = ProviderSessionId::new(conversation)?;
            let incarnation = serde_json::to_vec(&json!({
                "schema": "se.acp-completed-source/v1",
                "project": request.identity.project,
                "agent": request.identity.agent,
                "session": request.identity.session,
                "conversation": conversation,
                "lifecycle": attach.record.lifecycle,
                "root": attach.record.root,
                "owner": attach.record.owner
            }))
            .map_err(error)?;
            *binding
                .incarnation
                .lock()
                .map_err(|_| error("source state poisoned"))? = Some(incarnation);
            Ok(LaunchOutcome {
                witness: BindingWitness {
                    identity: request.identity,
                    conversation,
                    lifecycle: attach.record.lifecycle.clone(),
                    provider: ProviderVersion {
                        kind: HarnessKind::Acp,
                        executable: request.executable,
                        version: "agent version not queried".into(),
                        protocol: "ACP v1 (initialize witnessed)".into(),
                    },
                },
                binding: wrap(),
            })
        })
    }
    fn graceful_stop<'a>(
        &'a self,
        binding: &'a HarnessBinding,
        cx: CallContext,
    ) -> HostFuture<'a, ProviderInterrupt> {
        Box::pin(async move {
            let session = &bound(binding)?.session;
            let observation = session.observe()?;
            let conversation = ProviderSessionId::new(
                observation
                    .conversation
                    .ok_or_else(|| error("conversation identity is unavailable"))?,
            )?;
            let until = tokio::time::Instant::now() + cx.timeout;
            session
                .cancel(CallContext {
                    generation: cx.generation,
                    timeout: cx.timeout,
                    cancellation: cx.cancellation.clone(),
                })
                .await?;
            session
                .finish_input(CallContext {
                    timeout: until.saturating_duration_since(tokio::time::Instant::now()),
                    ..cx
                })
                .await?;
            Ok(ProviderInterrupt {
                conversation,
                requested: true,
                vendor_event: Read::Absent {
                    checked: "native exit is witnessed separately from protocol cancellation"
                        .into(),
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
            let session = &bound(binding)?.session;
            let until = tokio::time::Instant::now() + cx.timeout;
            let drained = session.drain_stream(&cx).await;
            session
                .close(CallContext {
                    timeout: until.saturating_duration_since(tokio::time::Instant::now()),
                    ..cx
                })
                .await?;
            drained
        })
    }
}

impl AdapterBinding for Arc<Binding> {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn provider(&self) -> se_types::Provider {
        se_types::Provider::Acp
    }
    fn arm(&self, wake: &Arc<tokio::sync::Notify>) -> Result<()> {
        self.session.arm(wake)
    }
    fn observe(&self, capture: bool) -> Observation {
        let observed = match self.session.observe() {
            Ok(observed) => observed,
            Err(error) => {
                return Observation {
                    failure: Some(error.body),
                    ..Default::default()
                };
            }
        };
        let completed = !observed.completed.is_empty();
        let mut result = Observation {
            idle: Some(observed.active_input.is_none() && !observed.cancelling),
            mail_pending: completed,
            capture_pending: completed && capture,
            ..Default::default()
        };
        if !capture {
            for request in &observed.completed {
                if let Err(error) = self.session.discard_after_capture_opt_out(*request) {
                    result.failure = Some(error.body);
                    break;
                }
            }
        }
        if let Some(failure) = observed.failure {
            result.failure = Some(failure);
        }
        result
    }
    fn stop_policy(&self) -> StopPolicy {
        StopPolicy::default()
    }
    fn start_initial(&self, cx: CallContext) -> HostFuture<'_, ()> {
        Box::pin(async move {
            let initial = self
                .initial
                .lock()
                .map_err(|_| error("input state poisoned"))?
                .take();
            if let Some((key, text)) = initial {
                // Taking the original key precedes I/O; uncertain offers are never repeated.
                self.session.prompt(key, text, cx).await?;
            }
            Ok(())
        })
    }
    fn policy_notice(&self) -> Result<Option<String>> {
        Ok(Some(self.session.observe()?.policy_notice.into()))
    }
}

fn attach_replay(request: &HarnessRequest) -> Result<Option<(&str, Vec<CapturedMessage>)>> {
    let replay: Option<(&str, Vec<CapturedMessage>)> = match &request.resume {
        Read::Present { value } => Some((
            value.as_str(),
            request
                .replay
                .clone()
                .ok_or_else(|| error("complete committed replay is required before resuming"))?,
        )),
        Read::Absent { .. } => None,
        Read::Unreadable { reason, .. } => return Err(error(reason)),
        Read::Unknown { what } => return Err(error(what)),
    };
    Ok(replay)
}
