//! Configured ACP executables use the same native launch lifecycle as stock harnesses.
use super::*;
use crate::acp::{CapturedMessage, Connection, PermissionPolicy, Session};
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
fn error(reason: impl std::fmt::Display) -> SeError {
    se_core::scope::unreadable("ACP binding", &reason.to_string())
}
impl AcpHarness {
    pub fn new(io: Arc<dyn ProviderIoPlatform>, configuration: ConfigFile, mcp_port: u16) -> Self {
        Self {
            io,
            configuration,
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
    pub(crate) fn validate_launch(
        configuration: &ConfigFile,
        named_profile: &str,
        model: Option<&str>,
        harness: Option<&str>,
    ) -> Result<ResolvedProfile> {
        let profile = configuration.resolve_profile(named_profile, Provider::Acp, true)?;
        let settings = configuration.acp_settings(harness, named_profile)?;
        let argument_model = settings.arguments.iter().any(|v| v.contains("{model}"));
        let configured_model = argument_model
            || settings
                .model_arguments
                .iter()
                .any(|v| v.contains("{model}"))
            || settings.model_environment.is_some();
        if model.is_some() && !configured_model {
            return Err(error(
                "The selected model requires an argv {model} slot or a native model_environment binding in this harness configuration.",
            ));
        }
        if argument_model && model.is_none() {
            return Err(error(
                "The selected harness's model binding requires a saved model. Select a model for this agent, or remove that binding to use the native harness default.",
            ));
        }
        Ok(profile)
    }
    pub(crate) async fn start_initial(
        &self,
        binding: &HarnessBinding,
        cx: CallContext,
    ) -> Result<()> {
        let binding = bound(binding)?;
        let initial = binding
            .initial
            .lock()
            .map_err(|_| error("input state poisoned"))?
            .take();
        if let Some((key, text)) = initial {
            // Taking the original key precedes stdio. An uncertain offer is never repeated.
            binding.session.prompt(key, text, cx).await?;
        }
        Ok(())
    }
}
pub(crate) fn bound(binding: &HarnessBinding) -> Result<&Arc<Binding>> {
    binding
        .acp
        .as_ref()
        .ok_or_else(|| error("the original protocol binding is absent"))
}
impl Harness for AcpHarness {
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
            environment.push((
                "SE_SESSION".into(),
                String::from_utf8(request.launch_credential.expose().to_vec())
                    .map_err(|_| error("launch capability is not UTF-8"))?
                    .into(),
            ));
            Ok(ProviderInvocation {
                executable: request.executable.clone(),
                arguments,
                environment: se_proc::Environment {
                    entries: environment,
                },
            })
        })
    }
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
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
            let session = Session::retain(
                connection,
                incoming,
                PermissionPolicy::from_saved_approval(resolved.approval),
            )
            .await;
            let binding = Arc::new(Binding {
                session,
                identity: request.identity.clone(),
                initial: Mutex::new(Some((
                    request.key.as_str().into(),
                    request.initial_input.as_str().into(),
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
            let wrap = || HarnessBinding {
                claude: None,
                codex: None,
                secode: None,
                acp: Some(binding.clone()),
                _private: (),
            };
            *retained = Some(wrap());
            let until = tokio::time::Instant::now() + cx.timeout;
            let remaining = || CallContext {
                generation: cx.generation,
                timeout: until.saturating_duration_since(tokio::time::Instant::now()),
                cancellation: cx.cancellation.clone(),
            };
            binding.session.initialize(remaining()).await?;
            let bearer = String::from_utf8(request.mcp_bearer.expose().to_vec())
                .map_err(|_| error("MCP capability is not UTF-8"))?;
            let proof = String::from_utf8(request.launch_credential.expose().to_vec())
                .map_err(|_| error("launch capability is not UTF-8"))?;
            let servers = vec![json!({
                "type": "http",
                "name": "stateengine",
                "url": format!("http://127.0.0.1:{}/mcp", self.mcp_port),
                "headers": [
                    {"name": "Authorization", "value": format!("Bearer {bearer}")},
                    {"name": "X-StateEngine-Session-Proof", "value": proof}
                ]
            })];
            let replay: Option<(&str, Vec<CapturedMessage>)> = match &request.resume {
                Read::Present { value } => Some((
                    value.as_str(),
                    request.replay.clone().ok_or_else(|| {
                        error("complete committed replay is required before resuming")
                    })?,
                )),
                Read::Absent { .. } => None,
                Read::Unreadable { reason, .. } => return Err(error(reason)),
                Read::Unknown { what } => return Err(error(what)),
            };
            let conversation = binding
                .session
                .open(
                    request
                        .cwd
                        .to_local()?
                        .to_str()
                        .ok_or_else(|| error("protocol cwd is not UTF-8"))?,
                    servers,
                    replay,
                    &self
                        .configuration
                        .acp_settings(
                            request.profile.harness.as_deref(),
                            &request.profile.named_profile,
                        )?
                        .mode,
                    remaining(),
                )
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
