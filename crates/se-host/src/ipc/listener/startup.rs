//! Keep a spare Windows pipe while the parent proves and commits its child.
//! Connected clients retain their place; no credentials or requests are read
//! until the normal post-commit handshake drives them.
use super::*;

pub(super) struct StartupClient {
    pub(super) stream: NativeStream,
    pub(super) incoming_slot: tokio::sync::OwnedSemaphorePermit,
}

impl IpcListener {
    pub(crate) async fn join_startup_refusals(&mut self, deadline: &Deadline) -> Result<()> {
        bounded(deadline, async {
            while let Some(joined) = self.startup_refusals.join_next().await {
                joined.map_err(|error| {
                    se_core::scope::unreadable("IPC startup refusal task", &error.to_string())
                })?;
            }
            Ok(())
        })
        .await?
    }

    pub(super) fn reap_startup_refusals(&mut self) -> Result<()> {
        while let Some(joined) = self.startup_refusals.try_join_next() {
            joined.map_err(|error| {
                se_core::scope::unreadable("IPC startup refusal task", &error.to_string())
            })?;
        }
        Ok(())
    }

    pub(super) async fn accept_pipe(&mut self) -> Result<NativeStream> {
        self.listener
            .connect()
            .await
            .map_err(|error| wire::io_failure("accept IPC", error))?;
        let entered = self.runtime.enter();
        let next = match evented_pipe(&self.native) {
            Ok(next) => next,
            Err(error) => {
                if let Err(disconnect) = self.listener.disconnect() {
                    return Err(se_core::scope::unreadable(
                        "IPC accept recovery",
                        &format!("{error}; could not reset accepted pipe: {disconnect}"),
                    ));
                }
                return Err(error);
            }
        };
        drop(entered);
        Ok(std::mem::replace(&mut self.listener, next))
    }

    pub(crate) async fn retain_startup_clients(&mut self, deadline: &Deadline) -> Result<()> {
        loop {
            self.reap_startup_refusals()?;
            let incoming_slot = bounded(deadline, self.incoming_slot()).await??;
            let stream = bounded(deadline, self.accept_pipe()).await??;
            // The same ingress capacity bounds handles before commit. Refuse
            // the oldest excess handshake without reading any operation bytes,
            // then keep driving the spare for the native startup parent.
            let oldest = if self.startup_clients.len() >= self.preauth.available_permits() {
                self.startup_clients.pop_front()
            } else {
                None
            };
            // Retain the new channel before any await. The independent task
            // below keeps its refused stream even when the commit wins.
            self.startup_clients.push_back(StartupClient {
                stream,
                incoming_slot,
            });
            if let Some(oldest) = oldest {
                // Reuse ordinary capacity refusal without native proof or
                // request reads. The task owns the extra incoming slot and its
                // original write clock independently of startup cancellation.
                let refused = AcceptedIpcStream {
                    stream: Arc::new(oldest.stream),
                    record: self.record.clone(),
                    runtime: self.runtime.clone(),
                    blocking: Arc::clone(&self.blocking),
                    preauth_slot: None,
                    incoming_slot: oldest.incoming_slot,
                    connections: Arc::clone(&self.connections),
                    deadline: deadline.stage(WRITE_TIMEOUT)?,
                };
                self.startup_refusals.spawn_on(
                    async move {
                        // Vanished peers and bounded silent-reader closes are
                        // local to this refused handshake, never a startup fence.
                        let _ = refused.handshake().await;
                    },
                    &self.runtime,
                );
            }
        }
    }
}
