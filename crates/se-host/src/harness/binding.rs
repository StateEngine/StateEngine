//! Adapter-owned lifecycle operations on the original retained streams.
use se_types::{ErrorBody, SeError};
use std::{any::Any, sync::Arc, time::Instant};
use tokio::sync::Notify;

#[derive(Default)]
pub(crate) struct Observation {
    pub observed_at: Option<Instant>,
    pub idle: Option<bool>,
    pub mail_pending: bool,
    pub capture_pending: bool,
    pub failure: Option<ErrorBody>,
    pub capture_failure: Option<SeError>,
}

#[derive(Clone, Copy)]
pub(crate) enum Signal {
    Interrupt,
    Terminate,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct StopPolicy {
    pub signal: Option<Signal>,
    pub native_window: bool,
}

pub(crate) trait AdapterBinding: Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn provider(&self) -> se_types::Provider;
    fn arm(&self, wake: &Arc<Notify>) -> se_types::Result<()>;
    fn observe(&self, capture: bool) -> Observation;
    fn stop_policy(&self) -> StopPolicy;
    fn start_initial(&self, _cx: crate::CallContext) -> crate::HostFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
    fn policy_notice(&self) -> se_types::Result<Option<String>> {
        Ok(None)
    }
}
