use super::managed::Binding;
use crate::harness::binding::{AdapterBinding, Observation, Signal, StopPolicy};
use se_types::Result;
use std::sync::Arc;

impl AdapterBinding for Arc<Binding> {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn provider(&self) -> se_types::Provider {
        se_types::Provider::SeCode
    }
    fn arm(&self, wake: &Arc<tokio::sync::Notify>) -> Result<()> {
        self.completion.arm(wake)
    }
    fn observe(&self, _capture: bool) -> Observation {
        let changed = self.completion.take();
        let failure = match self.diagnostics.lock() {
            Ok(diagnostics) => diagnostics.failure.clone(),
            Err(_) => Some(super::unreadable("SE Code stream state", "poisoned diagnostics").body),
        };
        Observation {
            mail_pending: changed,
            capture_pending: changed,
            failure,
            ..Default::default()
        }
    }
    fn stop_policy(&self) -> StopPolicy {
        StopPolicy {
            signal: Some(Signal::Interrupt),
            ..Default::default()
        }
    }
}
