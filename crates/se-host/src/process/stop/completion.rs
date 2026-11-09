//! Durable terminal publication, file retirement and native custody release.
use super::*;
use crate::state_files::{Acquisition, AcquisitionRetry};

#[derive(Clone)]
enum CleanupFile {
    SessionPin(se_types::SessionId, [u8; 32]),
    Launch(std::path::PathBuf, [u8; 32]),
}
impl CleanupFile {
    fn label(&self) -> &'static str {
        match self {
            Self::SessionPin(..) => "revoked session pin removal",
            Self::Launch(..) => "launch file cleanup",
        }
    }
    // Only acquisition errors reach the outer result and its retry policy.
    // Mutation failures remain public errors and are never replayed here.
    fn remove(
        &self,
        state: &se_proc::NativeStateFiles,
    ) -> std::result::Result<Result<()>, se_proc::StateFileError> {
        Ok(match self {
            Self::SessionPin(session, digest) => {
                se_proc::SessionPinRemoval::acquire(state, session)?
                    .remove(*digest)
                    .map_err(|e| error(self.label(), e))
            }
            Self::Launch(path, digest) => match se_proc::OwnedFile::open(path)? {
                Some(file) => file.remove(*digest).map_err(|e| error(self.label(), e)),
                None => Ok(()),
            },
        })
    }
}

impl LaunchCoordinator {
    pub(in crate::process) async fn finish(
        &self,
        work: &mut Work,
        witness: se_proc::StopWitness,
        deadline: &Deadline,
    ) -> Result<()> {
        if !work.session_retired {
            self.revoke_credentials(work, deadline).await?;
        }
        if work.meta.provider == se_store::Provider::SeCode {
            self.settle_secode(work, &witness, deadline).await?;
        }
        if work.native_already_reconciled && !work.session_retired {
            self.flush_capture(work, deadline).await.map_err(|failure| {
                let repair = se_core::ops::AgentCommand::stop_in_home(
                    &work.meta.agent.id,
                    &self.options.home,
                    &work.meta.project.id,
                )
                .map(|command| command.command)
                .unwrap_or_else(|| se_core::ops::AgentCommand::HOME_UNAVAILABLE.into());
                error("recovered final capture", format!(
                    "{failure}; session and original transcript remain pending, not retired. Restore access to the original transcript and protected binding, then retry: {repair}"
                ))
            })?;
        }
        if !work.process_retired {
            let previous = self.head(work, deadline).await?;
            let (retained, from) = match &previous.current.body {
                EventBody::ProcessRegistered { identity, initial } => (identity, *initial),
                EventBody::ProcessTransition { identity, to, .. } => (identity, *to),
                _ => {
                    return Err(se_core::scope::unreadable(
                        "exit publication",
                        "wrong retained process event",
                    ));
                }
            };
            let checkpoint = se_proc::decode_checkpoint(
                retained.custody.format_version,
                &retained.custody.record,
            )
            .map_err(|e| error("retained native checkpoint", e))?;
            if from == ProcessState::Exited {
                let CheckpointKind::Exit {
                    witness: previous_witness,
                    ..
                } = checkpoint.checkpoint
                else {
                    return Err(error(
                        "exit cleanup retry",
                        "terminal projection lacks its native witness",
                    ));
                };
                if previous_witness.lifecycle != witness.lifecycle
                    || previous_witness.scope != witness.scope
                {
                    return Err(error(
                        "exit cleanup retry",
                        "fresh witness differs from the retained scope",
                    ));
                }
                work.last_stop_event = Some(previous.current.header.event.clone());
                work.process_retired = true;
                work.last_witness = Some(witness.clone());
            } else {
                let source = match checkpoint.checkpoint {
                    CheckpointKind::Reservation(v) => CheckpointSource::Reservation(v),
                    CheckpointKind::Scope(v) => CheckpointSource::Scope(v),
                    CheckpointKind::Root(v) => CheckpointSource::Root(v),
                    CheckpointKind::Process(v) => CheckpointSource::Process(v),
                    _ => {
                        return Err(se_core::scope::unreadable(
                            "exit publication",
                            "retained source is already terminal",
                        ));
                    }
                };
                let root = match &witness.root {
                    se_proc::RootWitness::Identified { expected, .. } => Some(expected),
                    _ => None,
                };
                let argv = match &retained.instance {
                    se_store::RecordedIdentity::Present(value) => {
                        *value.fields().argv_sha256.as_bytes()
                    }
                    _ => [0; 32],
                };
                let identity = native_record::identity_meta(
                    &work.meta,
                    CheckpointKind::Exit {
                        source: Box::new(source),
                        witness: witness.clone(),
                    },
                    root.map(|root| (root, argv)),
                    Some(witness.guarantee),
                    &self.options.epoch.owner.fields().boot,
                )?;
                let event = self
                    .change(
                        work,
                        "exited",
                        identity,
                        (from, ProcessState::Exited),
                        deadline,
                    )
                    .await?;
                work.last_stop_event = Some(event);
                work.process_retired = true;
                work.last_witness = Some(witness.clone());
            }
        }
        if !work.session_retired {
            self.retire_session(work, "native scope exit witnessed", deadline)
                .await?;
        } else if work.capture_failure.is_some()
            && let Err(error) = self.flush_capture(work, deadline).await
            && work.capture_failure.is_none()
        {
            return Err(error);
        }
        self.retire_files(work, deadline).await?;
        if work.meta.provider == se_store::Provider::SeCode {
            self.secode_client_closed(work, &witness, deadline).await?;
        }
        if !work.native_already_reconciled {
            let native = self.native.clone();
            let process = work.process.clone().ok_or_else(|| {
                se_core::scope::unreadable("native release", "owned reference is absent")
            })?;
            self.store
                .pool
                .run_owned(deadline, move || {
                    native
                        .release(&process, &witness)
                        .map_err(|e| error("witnessed native release", e))
                })
                .await?;
        }
        work.released = true;
        work.active = false;
        work.binding = None;
        if work.meta.provider == se_store::Provider::SeCode {
            self.secode.retire(&work.meta.session)?;
        }
        work.process = None;
        Ok(())
    }
    pub(in crate::process) async fn retire_files(
        &self,
        work: &mut Work,
        deadline: &Deadline,
    ) -> Result<()> {
        self.retire_capture(work, deadline).await?;
        if !work.cleanup_files_known {
            self.restore_cleanup(work, deadline).await?;
        }
        if let Some(binding) = &work.binding {
            self.harness_for(work.meta.provider)?
                .close_binding(binding, call(self.store.generation, deadline)?)
                .await?;
        }
        let home = self.options.home.clone();
        let session = work.meta.session.clone();
        let pin = work.pin_hash;
        let files = work.files.clone();
        let codex = self.codex.clone();
        let is_codex = work.meta.provider == se_store::Provider::Codex;
        // Retain one absolute cleanup bound across every file, leaving time to
        // deliver a busy refusal before the caller's end-to-end request expires.
        let cleanup_deadline = deadline
            .at()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or(deadline.at());
        let state = self
            .store
            .pool
            .run_owned(deadline, move || {
                let state = se_proc::NativeStateFiles::open(&home)
                    .map_err(|e| error("session cleanup state", e))?;
                if is_codex {
                    codex.retire_socket(&session)?;
                }
                Ok(Arc::new(state))
            })
            .await?;
        let removals = pin
            .map(|pin| CleanupFile::SessionPin(work.meta.session.clone(), pin))
            .into_iter()
            .chain(
                files
                    .into_iter()
                    .map(|(path, digest)| CleanupFile::Launch(path, digest)),
            );
        for removal in removals {
            let mut retry = AcquisitionRetry::new(cleanup_deadline);
            loop {
                let state = state.clone();
                let operation = removal.clone();
                let (next, attempt) = self
                    .store
                    .pool
                    .run_owned(deadline, move || {
                        let result = retry.acquire(|| operation.remove(&state));
                        Ok((retry, result))
                    })
                    .await?;
                retry = next;
                match attempt
                    .map_err(|failure| failure.into_public(|e| error(removal.label(), e)))?
                {
                    Acquisition::Ready(result) => {
                        result?;
                        break;
                    }
                    Acquisition::Wait(delay) => tokio::time::sleep(delay).await,
                }
            }
        }
        Ok(())
    }
}
