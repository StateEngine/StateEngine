//! One real initialize/thread handshake, before or after console exec. Native
//! readiness and C3 stay with the coordinator; this never invents a ProcessRecord.
use super::*;
use crate::startup_timing::{Phase, Timing};

impl CodexHarness {
    pub fn attach_timed<'a>(
        &'a self,
        request: HarnessAttach,
        cx: CallContext,
        timing: &'a mut Timing,
    ) -> HostFuture<'a, LaunchOutcome> {
        Box::pin(async move {
            self.attach_transport(
                &request.request,
                request.transport,
                request.record.lifecycle,
                cx,
                timing,
            )
            .await
        })
    }

    pub async fn attach_transport(
        &self,
        request: &HarnessRequest,
        transport: ProviderTransport,
        lifecycle: se_types::LifecycleId,
        cx: CallContext,
        timing: &mut Timing,
    ) -> Result<LaunchOutcome> {
        let until = std::time::Instant::now() + cx.timeout;
        timing.advance(Phase::Transport);
        let provider = self
            .probed
            .lock()
            .map_err(|_| poisoned())?
            .as_ref()
            .map(|qualified| qualified.version.clone())
            .ok_or_else(|| {
                SeError::invalid("Codex attach", "an actual successful executable probe")
            })?;
        let socket = self.socket(request)?;
        let login = self
            .load_agent_login(&request.identity.session, until)
            .await?;
        let binding = self
            .connect(
                transport,
                socket.as_deref(),
                request.mode == se_proc::LaunchMode::Window,
                None,
                &login,
                &cx,
            )
            .await?;
        if let Some(socket) = &socket {
            let socket = socket.clone();
            let record = self
                .directory(&request.identity.session)?
                .join("codex-runtime.json");
            let session = request.identity.session.clone();
            let deadline = crate::Deadline::idle()?
                .stage(until.saturating_duration_since(std::time::Instant::now()))?;
            self.pool
                .run_owned(&deadline, move || {
                    Self::validate_socket(&socket, &record, &session)
                })
                .await?;
        }
        let cx = context(
            cx.generation,
            until.saturating_duration_since(std::time::Instant::now()),
        );
        timing.advance(Phase::Initialize);
        let handshake = tokio::time::timeout(cx.timeout, async {
            binding
                .request("initialize", input::initialize(), &cx)
                .await?;
            binding.notify("initialized", json!({}), &cx).await?;
            #[cfg(windows)]
            let named = self
                .windows_sandbox_selection(request, &login, until)
                .await?;
            #[cfg(windows)]
            self.confirm_windows_sandbox(&binding, named, &cx).await?;
            timing.advance(Phase::Thread);
            self.prepare_thread(request, &binding, socket.as_deref(), &cx)
                .await
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
                // Exclude connection teardown from the failed readiness phase.
                timing.freeze();
                let _ = close(&binding, &cx).await;
                return Err(error);
            }
        };
        timing.advance(Phase::Publication);
        Ok(LaunchOutcome {
            witness: BindingWitness {
                identity: request.identity.clone(),
                conversation,
                lifecycle,
                provider,
            },
            binding: HarnessBinding::new(binding),
        })
    }

    async fn load_agent_login(
        &self,
        session: &se_types::SessionId,
        until: std::time::Instant,
    ) -> Result<PathBuf> {
        let path = self.directory(session)?.join(LOGIN_RECORD);
        let session = session.clone();
        let deadline = crate::Deadline::idle()?
            .stage(until.saturating_duration_since(std::time::Instant::now()))?;
        let recorded = self
            .pool
            .run_owned(&deadline, move || Self::read_agent_login(&path, &session))
            .await?;
        se_core::scope::require_present(
            recorded,
            "Codex login record",
            "Relaunch the agent; its launch did not record a Codex login.",
        )
    }

    #[cfg(windows)]
    async fn windows_sandbox_selection(
        &self,
        request: &HarnessRequest,
        login: &Path,
        until: std::time::Instant,
    ) -> Result<Option<windows_sandbox::Implementation>> {
        if !matches!(
            request.policy.writes,
            se_proc::WritePolicy::Workspace { .. }
        ) {
            return Ok(None);
        }
        let login = login.to_path_buf();
        let deadline = crate::Deadline::idle()?
            .stage(until.saturating_duration_since(std::time::Instant::now()))?;
        let choice = self
            .pool
            .run_owned(&deadline, move || windows_sandbox::user_choice(&login))
            .await?;
        Ok(Some(
            choice.unwrap_or(windows_sandbox::Implementation::DEFAULT),
        ))
    }

    async fn prepare_thread(
        &self,
        request: &HarnessRequest,
        binding: &Binding,
        socket: Option<&Path>,
        cx: &CallContext,
    ) -> Result<ProviderSessionId> {
        let resolved = self.resolved(request)?;
        let plan = self.plan(request, &resolved, socket);
        let (method, mut params) = self.thread(&plan)?;
        // The thread's StateEngine server must not meet the user's own servers:
        // the login's registration is switched off, and the host's takes a free name.
        let read = json!({"cwd": params["cwd"].clone()});
        match binding.request_classified("config/read", read, cx).await {
            Ok(effective) => se_mcp::client::codex_fit(&effective, &mut params["config"])?,
            // Older Codex cannot report its configuration; keep the default name.
            Err(failure) if failure.code == Some(-32601) => {}
            Err(failure) => return Err(failure.error),
        }
        let response = binding.request(method, params, cx).await?;
        let conversation = input::verify_thread(&plan, &response)?;
        binding.state.lock().map_err(|_| poisoned())?.conversation = Some(conversation.clone());
        if let Some(path) = response.pointer("/thread/path").and_then(Value::as_str) {
            *binding.rollout.lock().map_err(|_| poisoned())? =
                Some(NativePath::from_local(PathBuf::from(path))?);
        }
        let mut initial = input::turn(&plan, &conversation, &request.initial_input)?;
        initial["clientUserMessageId"] = json!(format!(
            "se-{}",
            se_types::hex_lower(&Sha256::digest(request.key.as_str().as_bytes()))
        ));
        *binding.initial.lock().await = Some(initial);
        Ok(conversation)
    }
}
