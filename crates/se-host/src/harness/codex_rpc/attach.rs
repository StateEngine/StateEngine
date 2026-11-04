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
            .clone()
            .ok_or_else(|| {
                SeError::invalid("Codex attach", "an actual successful executable probe")
            })?;
        let socket = self.socket(request)?;
        let port = Arc::new(transport);
        let (sender, receiver) =
            channel::open(self.io.clone(), port.clone(), socket.as_deref(), &cx).await?;
        if let Some(socket) = &socket {
            let socket = socket.clone();
            let runtime_record = self
                .directory(&request.identity.session)?
                .join("codex-runtime.json");
            let session = request.identity.session.clone();
            let deadline = crate::client::lease::Deadline::idle()?
                .stage(until.saturating_duration_since(std::time::Instant::now()))?;
            self.pool
                .run_owned(&deadline, move || {
                    Self::validate_socket(&socket, &runtime_record, &session)
                })
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
            state: Mutex::new(state::State {
                capture: self.configuration.capture.enabled,
                ..Default::default()
            }),
            completion: Default::default(),
            rollout: Mutex::new(None),
            initial: tokio::sync::Mutex::new(None),
            input: tokio::sync::Mutex::new(()),
            tasks: Mutex::new(vec![]),
            attended: request.mode == se_proc::LaunchMode::Window,
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
            let resolved = self.resolved(request)?;
            let plan = self.plan(request, &resolved, socket.as_deref());
            let (method, params) = input::thread(&plan)?;
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
                _private: (),
            },
        })
    }
}
