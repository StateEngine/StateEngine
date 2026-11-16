use super::*;
use crate::harness::binding::{AdapterBinding, Observation, StopPolicy};

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
