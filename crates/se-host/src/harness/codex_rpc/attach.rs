//! One real initialize/thread handshake, before or after console exec. Native
//! readiness and C3 stay with the coordinator; this never invents a ProcessRecord.
use super::*;
impl CodexHarness {
    pub(crate) async fn attach_transport(
        &self,
        request: &HarnessRequest,
        transport: ProviderTransport,
        lifecycle: se_types::LifecycleId,
        cx: CallContext,
    ) -> Result<LaunchOutcome> {
        let until = std::time::Instant::now() + cx.timeout;
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
        let binding = self
            .connect(
                transport,
                socket.as_deref(),
                request.mode == se_proc::LaunchMode::Window,
                None,
                &cx,
            )
            .await?;
        if let Some(socket) = &socket {
            let socket = socket.clone();
            let record = self
                .directory(&request.identity.session)?
                .join("codex-runtime.json");
            let session = request.identity.session.clone();
            let deadline = crate::client::lease::Deadline::idle()?
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
        let handshake = tokio::time::timeout(cx.timeout, async {
            binding
                .request("initialize", input::initialize(), &cx)
                .await?;
            binding.notify("initialized", json!({}), &cx).await?;
            #[cfg(windows)]
            let named = windows_sandbox::selection(request)?;
            #[cfg(windows)]
            self.confirm_windows_sandbox(&binding, named, &cx).await?;
            let resolved = self.resolved(request)?;
            let plan = self.plan(request, &resolved, socket.as_deref());
            let (method, params) = self.thread(&plan)?;
            let response = binding.request(method, params, &cx).await?;
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
                identity: request.identity.clone(),
                conversation,
                lifecycle,
                provider,
            },
            binding: HarnessBinding {
                claude: None,
                codex: Some(binding),
                secode: None,
                acp: None,
                _private: (),
            },
        })
    }
}
