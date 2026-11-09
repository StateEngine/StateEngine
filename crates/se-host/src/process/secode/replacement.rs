//! An explicitly fresh conversation may follow a proved, captured stop. It
//! never releases the old conversation's human hold or replays its input.
use super::*;
use se_store::{EventBody, Snapshot};
use se_types::Read;
use sha2::{Digest, Sha256};

impl LaunchCoordinator {
    pub(in crate::process) async fn secode_client_closed(
        &self,
        work: &owned::Work,
        witness: &se_proc::StopWitness,
        deadline: &Deadline,
    ) -> Result<()> {
        let Some(slot) = self
            .secode_services
            .get(&work.meta.project.id, &work.meta.agent.id, deadline)
            .await?
        else {
            return if matches!(witness.root, se_proc::RootWitness::NoChildCreated) {
                Ok(())
            } else {
                Err(error(
                    "SE Code client closure",
                    "original private custody absent",
                ))
            };
        };
        let mut service = lock_service(&slot, deadline).await?;
        if witness.lifecycle != work.meta.lifecycle {
            return Err(error(
                "SE Code client closure",
                "original lifecycle differs",
            ));
        }
        if service.journal.session != work.meta.session {
            // A rejected replacement can fail before acquiring the service
            // journal. Its proved no-child reservation has no provider input
            // to settle and cannot overwrite its predecessor's closure.
            return if matches!(witness.root, se_proc::RootWitness::NoChildCreated) {
                Ok(())
            } else {
                Err(error("SE Code client closure", "original session differs"))
            };
        }
        service.journal.client_closed = Some(custody::ClientClosed {
            witness: witness.clone(),
            capture_complete: work.capture_failure.is_none()
                && (work.capture_flushed || !work.meta.capture || !work.activated),
        });
        service.persist(self, deadline).await
    }

    pub(super) async fn replace_secode_session(
        &self,
        service: &mut Service,
        work: &owned::Work,
        request: &crate::HarnessRequest,
        deadline: &Deadline,
    ) -> Result<()> {
        let resuming = match &request.resume {
            Read::Present { value } if value.as_str() == service.journal.vendor_session => true,
            Read::Absent { .. } => false,
            _ => {
                return Err(error(
                    "SE Code session replacement",
                    "resume does not name the original retained conversation; no input was offered",
                ));
            }
        };
        if service
            .journal
            .resume_release
            .as_ref()
            .is_some_and(|release| {
                !release.completed && (!resuming || release.session != request.identity.session)
            })
        {
            return Err(error(
                "SE Code session replacement",
                "the original hold release is still uncertain; retain its exact coordinates before replacing the session",
            ));
        }
        let closed = service
            .journal
            .client_closed
            .as_ref()
            .filter(|closed| closed.capture_complete)
            .ok_or_else(|| {
                error(
                    "SE Code session replacement",
                    "original client absence and final capture are not both proved",
                )
            })?;
        if !matches!(
            closed.witness.root,
            se_proc::RootWitness::Identified { .. } | se_proc::RootWitness::NoChildCreated
        ) {
            return Err(error(
                "SE Code session replacement",
                "original unpublished client scope cannot establish absence of an uncertain input",
            ));
        }
        let old = service.journal.session.clone();
        self.store.read(work.cleanup_admission.clone(), deadline, move |cx| {
            let session = se_core::scope::require_present(cx.read.session(old.clone()).map_err(|e| se_core::store_error::store_error(&e))?, "SE Code predecessor", "Reconcile the original session before replacement.")?;
            if !matches!(&session.current.body, EventBody::SessionEnded {session,..} | EventBody::SessionRevoked {session,..} if session==&old) {
                return Err(error("SE Code session replacement", "original engine session is not terminal"));
            }
            let original = session.original.as_deref().unwrap_or(&session.current);
            match &original.body {
                EventBody::SessionPrepared { provider:se_store::Provider::SeCode, consent:se_store::Consent::Capture, .. }
                    if matches!(session.current.body, EventBody::SessionEnded { .. }) => {
                    let source = se_core::ops::process_commit::session_credential_id(&old, "capture-source")?;
                    match cx.read.capture_outcome(source, None).map_err(|e| se_core::store_error::store_error(&e))? {
                        Read::Present { value } if matches!(&value.body, EventBody::CaptureVerified {session,..} if session==&old) => (),
                        _ => return Err(error("SE Code session replacement", "original final capture is unverified or failed; preserve its service and cursor")),
                    }
                }
                EventBody::SessionPrepared { provider:se_store::Provider::SeCode, .. } => (),
                _ => return Err(error("SE Code session replacement", "original provider preparation differs")),
            }
            Ok(())
        }).await?;
        let no_service_or_input =
            !service.journal.initial_offered && !service.journal.session_create_attempted;
        if resuming
            && (no_service_or_input || service.journal.retired || service.journal.notice.is_some())
        {
            return Err(error(
                "SE Code resume",
                "the original service and input must remain available and any original notice must be resolved before replacing its capability binding",
            ));
        }
        if !no_service_or_input && !service.journal.retired {
            let control = service.control.as_ref().ok_or_else(|| {
                error(
                    "SE Code session replacement",
                    "original authenticated service is unavailable",
                )
            })?;
            let identity = service.journal.identity.as_ref().ok_or_else(|| {
                error(
                    "SE Code session replacement",
                    "original service identity absent",
                )
            })?;
            let before = control
                .binding(&service.journal.vendor_session, deadline)
                .await?;
            identity.require_same(&before.service)?;
            if before.status == crate::harness::secode_process::NoticeStatus::Ready
                && !(resuming
                    && service
                        .journal
                        .resume_release
                        .as_ref()
                        .is_some_and(|release| {
                            !release.completed && release.session == request.identity.session
                        }))
            {
                return Err(error(
                    "SE Code session replacement",
                    "old native work is not held",
                ));
            }
            let active = control
                .read(&["api", "session", "active"], deadline)
                .await?;
            let active = active["data"].as_object().ok_or_else(|| {
                error(
                    "SE Code session replacement",
                    "complete execution map absent",
                )
            })?;
            if active.contains_key(&service.journal.vendor_session) {
                return Err(error(
                    "SE Code session replacement",
                    "old service execution is still active",
                ));
            }
            let after = control
                .binding(&service.journal.vendor_session, deadline)
                .await?;
            identity.require_same(&after.service)?;
            if resuming {
                self.release_secode_hold(service, request, after, deadline)
                    .await?;
            }
        }
        if service.journal.retired {
            service.journal.service = None;
            service.journal.endpoint = None;
            service.journal.identity = None;
            service.journal.registration = None;
            service.journal.server_sha256 = None;
            service.journal.retirement = None;
            service.control = None;
            service.failure = None;
            service.journal.retired = false;
            service.journal.stop_failure = None;
        }
        service.journal.session = request.identity.session.clone();
        service.journal.vendor_session = crate::harness::secode_process::vendor_session(request)?;
        service.journal.initial_input = crate::harness::secode_process::initial_input(request);
        service.journal.initial_sha256 = se_types::Sha256::from_bytes(
            Sha256::digest(request.initial_input.as_str().as_bytes()).into(),
        );
        service.journal.initial_offered = false;
        service.journal.session_create_attempted = false;
        service.journal.previous_policy_sha256 = service.journal.policy_sha256.take();
        service.journal.client_closed = None;
        service.journal.notice = None;
        service.persist(self, deadline).await
    }
}
