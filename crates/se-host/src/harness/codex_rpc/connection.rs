//! One connection constructor for fresh launch and verified restart adoption.
use super::*;
impl CodexHarness {
    pub(super) async fn connect(
        &self,
        transport: ProviderTransport,
        socket: Option<&Path>,
        attended: bool,
        recovery: Option<ProviderSessionId>,
        cx: &CallContext,
    ) -> Result<Arc<Binding>> {
        let draining = recovery.is_none();
        let port = Arc::new(transport);
        let (sender, receiver) = channel::open(self.io.clone(), port.clone(), socket, cx).await?;
        let restoring = recovery.is_some();
        let binding = Arc::new(Binding {
            io: self.io.clone(),
            port: draining.then(|| port.clone()),
            sender: tokio::sync::Mutex::new(sender),
            state: Mutex::new(state::State {
                capture: self.configuration.capture.enabled,
                conversation: recovery,
                restoring,
                ..Default::default()
            }),
            completion: Default::default(),
            rollout: Mutex::new(None),
            initial: tokio::sync::Mutex::new(None),
            input: tokio::sync::Mutex::new(()),
            tasks: Mutex::new(vec![]),
            attended,
            #[cfg(feature = "remote")]
            live: Default::default(),
        });
        let mut tasks = vec![tokio::spawn(rpc::read(
            Arc::downgrade(&binding),
            receiver,
            cx.generation,
        ))];
        if draining {
            tasks.push(tokio::spawn(channel::drain(
                self.io.clone(),
                port.clone(),
                ProviderStream::Error,
                cx.generation,
            )));
            if socket.is_some() {
                tasks.push(tokio::spawn(channel::drain(
                    self.io.clone(),
                    port,
                    ProviderStream::Output,
                    cx.generation,
                )));
            }
        }
        *binding.tasks.lock().map_err(|_| poisoned())? = tasks;
        Ok(binding)
    }
}
