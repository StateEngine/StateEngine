//! Verify a live retry through the existing protected source, never its payload.
use super::*;

impl CaptureHandle {
    pub(crate) async fn unresolved_at_eof(
        &self,
        admission: se_store::Admission,
        deadline: &Deadline,
    ) -> Result<Option<(u64, se_types::EventId)>> {
        let session = admission
            .session
            .as_ref()
            .ok_or_else(|| SeError::invalid("capture verification", "the admitted session"))?;
        let pin = self.sources.get(session)?;
        let context = self.execution.clone();
        let bound = deadline.clone();
        self.execution
            .blocking
            .run_owned(deadline, move || {
                let mut source = try_guard(&pin)?;
                source::unresolved_at_eof(&context, &admission, &mut source, &bound)
            })
            .await
    }
}
