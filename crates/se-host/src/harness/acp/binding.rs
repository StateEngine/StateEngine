use super::*;
use crate::harness::binding::{AdapterBinding, Observation, StopPolicy};

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
