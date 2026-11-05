//! Authorize and durably request stop before interrupting a retained handshake.
//! Never cancel a native allocation or an accepted writer completion.
use super::{supervisor::Job, *};
use crate::client::lease::Deadline;
use se_core::{ops::process_commit, scope, store_error::store_error};
use se_store::{Admission, EventBody, ProcessState, Snapshot};
use se_types::{Detail, IdempotencyKey, Result};

impl LaunchCoordinator {
    pub(super) async fn stop_startups(&self, deadline: &Deadline) -> Result<()> {
        self.stopping
            .store(true, std::sync::atomic::Ordering::Release);
        let jobs = self
            .jobs
            .0
            .lock()
            .map_err(|_| error("startup shutdown", "poisoned job registry"))?
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut failure = None;
        for job in jobs {
            let result = self
                .interrupt_startup(
                    &job,
                    &format!("shutdown-startup-{}", job.lifecycle).parse()?,
                    Admission {
                        actor: se_store::Actor::Human(self.human.clone()),
                        scope: se_store::Scope::Project(job.target.0.clone()),
                        session: None,
                        generation: self.store.generation.get(),
                    },
                    deadline,
                )
                .await;
            if let Err(error) = result {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
    pub(super) async fn interrupt_startup(
        &self,
        job: &Arc<Job>,
        key: &IdempotencyKey,
        admission: Admission,
        deadline: &Deadline,
    ) -> Result<()> {
        loop {
            if job.ready.borrow().is_some() {
                return Ok(());
            }
            let agent = job.target.1.clone();
            let lifecycle = job.lifecycle.clone();
            let previous = self
                .store
                .read(admission.clone(), deadline, move |cx| {
                    let current = scope::require_present(
                        cx.read.control_target(agent).map_err(|e| store_error(&e))?,
                        "startup stop control",
                        "Restore the current control grant or use the owner terminal.",
                    )?;
                    Ok(current
                        .processes
                        .into_iter()
                        .find(|head| match &head.current.body {
                            EventBody::ProcessRegistered { identity, .. }
                            | EventBody::ProcessTransition { identity, .. } => {
                                identity.record == lifecycle
                            }
                            _ => false,
                        }))
                })
                .await?;
            let Some(previous) = previous else {
                return Ok(());
            };
            let identity = match &previous.current.body {
                EventBody::ProcessTransition {
                    identity,
                    to: ProcessState::Starting,
                    ..
                } => identity.as_ref().clone(),
                _ => return Ok(()),
            };
            // Before exec publication the coordinator must still join native
            // allocation. Its original bound and retained cleanup remain owned.
            let checkpoint = se_proc::decode_checkpoint(
                identity.custody.format_version,
                &identity.custody.record,
            )
            .map_err(|e| error("startup stop custody", e))?;
            if !matches!(checkpoint.checkpoint, se_proc::CheckpointKind::Process(_)) {
                return Ok(());
            }
            let request = key.clone();
            let committed = self
                .store
                .commit(admission.clone(), deadline, None, move |kernel, cx| {
                    process_commit::advance(
                        kernel,
                        process_commit::ProcessChange {
                            request,
                            phase: "startup-stop-requested",
                            previous,
                            identity,
                            edge: (ProcessState::Starting, ProcessState::StopRequested),
                        },
                        cx,
                    )
                })
                .await;
            match committed {
                Ok(_) => {
                    job.wake.request_startup_stop();
                    return Ok(());
                }
                // Activation can win the CAS. Re-read that exact lifecycle and
                // take its ordinary active-stop path; never cancel on a refusal.
                Err(error) if matches!(error.body.detail(), Detail::RevisionConflict(_)) => {
                    continue;
                }
                Err(error) => return Err(error),
            }
        }
    }
}
