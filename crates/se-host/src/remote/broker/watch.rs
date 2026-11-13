//! Native local-watch opener; page retention and validation live in the broker.
use super::*;
#[derive(Default)]
pub(crate) struct Watches {
    inner: se_remote::broker::watch::Watches,
}
impl Watches {
    pub(crate) fn close(&self) -> Result<()> {
        self.inner.close()
    }
    #[cfg(feature = "remote")]
    pub(crate) async fn read_local(
        &self,
        admission: &se_store::Admission,
        service: service::Service,
        selection: (RemoteWatch, Option<[u8; 16]>),
        wait_ms: u32,
        deadline: &crate::client::lease::Deadline,
    ) -> Result<RemoteWatchBatch> {
        let (request, reader_id) = selection;
        let key = serde_json::to_string(&serde_json::json!({
            "native_owner":admission.actor,"generation":admission.generation,
            "targets":request.targets,"visible":request.visible,"measure":request.measure,"reader":reader_id,
        }))
        .map_err(|_| poisoned())?;
        let admission = admission.clone();
        self.inner
            .read_with(key, None, request, wait_ms, deadline, move |_, request| {
                Box::pin(async move { service.watch_local(admission, request) })
            })
            .await
    }
}
fn poisoned() -> SeError {
    refused("source broker state is unreadable")
}
