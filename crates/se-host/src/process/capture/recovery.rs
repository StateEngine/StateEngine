//! A terminal session can retain capture debt after its native scope is empty.
use super::*;
use se_store::{EventBody, Snapshot};
impl LaunchCoordinator {
    pub(in crate::process) async fn restore_capture_status(
        &self,
        work: &mut Work,
        deadline: &Deadline,
    ) -> Result<()> {
        if !work.meta.capture || !work.activated || !work.session_retired {
            return Ok(());
        }
        let session = work.meta.session.clone();
        let source_id =
            se_core::ops::process_commit::session_credential_id(&session, "capture-source")?;
        let read_bound = deadline.remaining()?.min(std::time::Duration::from_secs(5));
        let failure = self
            .store
            .read(work.cleanup_admission.clone(), deadline, move |cx| {
                let source = se_core::scope::require_present(
                    cx.read
                        .capture_source(source_id)
                        .map_err(|cause| se_core::store_error::store_error(&cause))?,
                    "retained final capture",
                    "Restore the original capture source and its committed cursor.",
                )?;
                let failures = cx
                    .read
                    .history(
                        se_store::HistoryQuery {
                            agent: None,
                            session: Some(session.clone()),
                            kinds: vec![se_store::EventKind::CaptureFailed],
                            families: Vec::new(),
                            transcript: se_store::TranscriptFilter::All,
                            since: Some(source.current.position),
                        },
                        se_store::ReadBudget {
                            page: se_types::PageRequest {
                                after: None,
                                limit: std::num::NonZeroU32::new(1).ok_or_else(|| {
                                    error("capture recovery", "positive diagnostic limit")
                                })?,
                                max_bytes: std::num::NonZeroU32::new(32 * 1024).ok_or_else(
                                    || error("capture recovery", "positive diagnostic byte bound"),
                                )?,
                            },
                            deadline: read_bound,
                        },
                    )
                    .map_err(|cause| se_core::store_error::store_error(&cause))?;
                match failures.items().first().map(|event| &event.body) {
                    Some(EventBody::CaptureFailed {
                        source,
                        session: found,
                        code,
                        cause,
                        ..
                    }) if *source == source_id && found == &session => Ok(Some(
                        error("retained final capture", format!("{code:?}: {cause}")).body,
                    )),
                    None => Ok(None),
                    _ => Err(error(
                        "retained final capture",
                        "the exact session/source diagnostic",
                    )),
                }
            })
            .await?;
        work.capture_flushed = failure.is_none();
        work.capture_failure = failure;
        Ok(())
    }
}
