//! Human resume releases the exact retained stop before capability replacement.
//! A lost response is read back; neither input nor a later hold is retried.
use super::*;
use crate::harness::secode_process::{NoticeBinding, probe};

impl LaunchCoordinator {
    pub(super) async fn release_secode_hold(
        &self,
        service: &mut Service,
        request: &crate::HarnessRequest,
        current: NoticeBinding,
        deadline: &Deadline,
    ) -> Result<()> {
        let qualified = service.current()?;
        let control = qualified.control.clone();
        let pending = service
            .journal
            .resume_release
            .as_ref()
            .filter(|release| !release.completed)
            .cloned();
        let (original, offered) = if let Some(pending) = pending {
            if pending.session != request.identity.session {
                return Err(error(
                    "SE Code resume",
                    "an original hold release remains uncertain; reconcile its exact coordinates without another release",
                ));
            }
            (pending.binding, false)
        } else {
            current.require_held()?;
            let server = match service.journal.service.as_ref().map(|c| &c.checkpoint) {
                Some(se_proc::CheckpointKind::Process(record)) => record.root.image.clone(),
                _ => {
                    return Err(error(
                        "SE Code resume",
                        "the original native service process is unavailable",
                    ));
                }
            };
            if !probe::supports_resume(&probe::capabilities(&server, deadline).await?) {
                return Err(crate::harness::secode_process::incompatible(
                    "the retained service has no fenced input-free hold release",
                ));
            }
            service.journal.resume_release = Some(custody::ResumeRelease {
                session: request.identity.session.clone(),
                binding: current.clone(),
                completed: false,
            });
            service.persist(self, deadline).await?;
            (current, true)
        };
        let write_error = if offered {
            control.release_hold(&original, deadline).await.err()
        } else {
            None
        };
        let after = qualified
            .binding(&original.session_id, deadline)
            .await
            .and_then(|after| after.require_released(&original));
        if let Err(read) = after {
            return Err(match write_error {
                Some(write) => read.with_cause(write),
                None => read,
            });
        }
        let release = service
            .journal
            .resume_release
            .as_mut()
            .ok_or_else(|| error("SE Code resume", "original release intent is unavailable"))?;
        release.completed = true;
        service.persist(self, deadline).await
    }
}
