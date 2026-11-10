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
        let requires_verification = matches!(
            work.meta.provider,
            se_store::Provider::SeCode | se_store::Provider::Acp
        );
        let failure = self
            .store
            .read(work.cleanup_admission.clone(), deadline, move |cx| {
                let outcome = cx
                    .read
                    .capture_outcome(source_id, None)
                    .map_err(|cause| se_core::store_error::store_error(&cause))?;
                let event = match &outcome {
                    se_types::Read::Present { value } => Some(&value.body),
                    se_types::Read::Absent { .. } => None,
                    _ => {
                        return Err(error(
                            "retained final capture",
                            "the latest capture outcome is unavailable",
                        ));
                    }
                };
                match event {
                    Some(EventBody::CaptureFailed {
                        source,
                        session: found,
                        code,
                        cause,
                        ..
                    }) if *source == source_id && found == &session => Ok(Some(
                        error("retained final capture", format!("{code:?}: {cause}")).body,
                    )),
                    Some(EventBody::CaptureVerified {
                        source,
                        session: found,
                        ..
                    }) if *source == source_id && found == &session => Ok(None),
                    None if requires_verification => Err(error(
                        "retained final capture",
                        "no EOF verification exists for the original authenticated source",
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
