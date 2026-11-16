use super::*;
use crate::harness::binding::{AdapterBinding, Observation, StopPolicy};

impl AdapterBinding for Arc<Binding> {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn provider(&self) -> se_types::Provider {
        se_types::Provider::Claude
    }
    fn arm(&self, wake: &Arc<tokio::sync::Notify>) -> Result<()> {
        self.completion.arm(wake)
    }
    fn observe(&self, _capture: bool) -> Observation {
        match self.completion.take() {
            Ok(Some(observed)) => Observation {
                observed_at: Some(observed.observed_at),
                idle: Some(observed.completed),
                mail_pending: observed.completed,
                capture_pending: true,
                ..Default::default()
            },
            Ok(None) => Observation::default(),
            Err(error) => Observation {
                capture_failure: Some(error),
                ..Default::default()
            },
        }
    }
    fn stop_policy(&self) -> StopPolicy {
        StopPolicy {
            native_window: self.attended,
            ..Default::default()
        }
    }
}
