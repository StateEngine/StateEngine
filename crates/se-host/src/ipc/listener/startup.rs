//! Keep a spare Windows pipe while the parent proves and commits its child.
//! Connected clients retain their place; no credentials or requests are read
//! until the normal post-commit handshake drives them.
use super::*;

/// The commit select may cancel pre-commit acceptance during a refusal. Keep
/// that exact write future and clock owned until admission or joined closure.
pub(super) struct StartupRefusal {
    delivery: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + Sync>>,
}

impl IpcListener {
    pub(super) async fn finish_startup_refusal(&mut self) {
        if let Some(refusal) = &mut self.startup_refusal {
            refusal.delivery.as_mut().await;
        }
        self.startup_refusal = None;
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
            self.finish_startup_refusal().await;
            deadline.remaining()?;
            let stream = self.accept_pipe().await?;
            // The same ingress capacity bounds handles before commit. Refuse
            // the oldest excess handshake without reading any operation bytes,
            // then keep driving the spare for the native startup parent.
            let oldest = if self.startup_clients.len() >= self.preauth.available_permits() {
                self.startup_clients.pop_front()
            } else {
                None
            };
            // Retain the new channel before any await. The ownership commit
            // can finish during a refusal write and cancel this future.
            self.startup_clients.push_back(stream);
            if let Some(oldest) = oldest {
                let error = capacity_error("IPC startup handshake capacity is occupied");
                let envelope =
                    se_types::ErrorEnvelope::new(error.body, &se_types::RenderCx::default())?;
                let frame = auth::encode_hello_refusal(&envelope)?;
                let write = deadline.stage(WRITE_TIMEOUT)?;
                self.startup_refusal = Some(StartupRefusal {
                    delivery: Box::pin(async move {
                        // A vanished peer or silent-reader timeout is local to
                        // this refusal. Neither renews the startup clock.
                        let _ = send_refusal(&oldest, &frame, &write).await;
                    }),
                });
            }
        }
    }
}
