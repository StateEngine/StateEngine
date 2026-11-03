//! An owner explicitly relinquishes an unproved tracked scope. The durable
//! release remains StopUnproved and never becomes an empty-scope witness.
use super::launch::Work;
use super::*;
use crate::client::lease::Deadline;
use se_core::ops::agent_stop::{AgentStopResult, OwnershipRelease, StopWitness};
use se_proc::{CheckpointKind, ProcessRuntime, StopObservation};
use se_store::{Actor, EventBody, ProcessState};
use se_types::{Result, SeError};
use std::num::NonZeroU64;

impl LaunchCoordinator {
    pub(super) async fn release_target(
        &self,
        work: &mut Work,
        row: &mut AgentStopResult,
        deadline: &Deadline,
    ) -> Result<()> {
        if !matches!(work.admission.actor, Actor::Human(_)) {
            return Err(SeError::invalid(
                "ownership release",
                "the independently verified owner's human terminal",
            ));
        }
        let previous = self.head(work, deadline).await?;
        let EventBody::ProcessTransition {
            to: ProcessState::StopUnproved,
            identity,
            ..
        } = &previous.current.body
        else {
            return Err(SeError::invalid(
                "ownership release",
                "first attempt an ordinary stop and retain its durable StopUnproved result",
            ));
        };
        let mut checkpoint =
            se_proc::decode_checkpoint(identity.custody.format_version, &identity.custody.record)
                .map_err(|e| error("release custody", e))?;
        let (source, scope, existing) = match checkpoint.checkpoint.clone() {
            CheckpointKind::Released { source, release } => {
                let scope = release.scope.clone();
                (source, scope, Some(release))
            }
            CheckpointKind::Process(record) => {
                let scope = record.scope.clone();
                let existing = record.ownership_release.clone();
                (
                    Box::new(se_proc::CheckpointSource::Process(record)),
                    scope,
                    existing,
                )
            }
            CheckpointKind::Scope(scope) => {
                let name = scope.scope.clone();
                (
                    Box::new(se_proc::CheckpointSource::Scope(scope)),
                    name,
                    None,
                )
            }
            CheckpointKind::Root(root) => {
                let scope = root.scope.scope.clone();
                (Box::new(se_proc::CheckpointSource::Root(root)), scope, None)
            }
            CheckpointKind::Reservation(reservation) => {
                let scope = match reservation.parent {
                    se_proc::ReservationParent::LinuxTracked => {
                        se_proc::ScopeIdentity::LinuxPrepared {
                            nonce: reservation.scope_nonce,
                        }
                    }
                    se_proc::ReservationParent::MacOs => se_proc::ScopeIdentity::MacOsPrepared {
                        nonce: reservation.scope_nonce,
                    },
                    _ => {
                        return Err(SeError::invalid(
                            "ownership release",
                            "an explicitly uncontained reservation",
                        ));
                    }
                };
                (
                    Box::new(se_proc::CheckpointSource::Reservation(reservation)),
                    scope,
                    None,
                )
            }
            _ => {
                return Err(SeError::invalid(
                    "ownership release",
                    "unresolved native custody, never a terminal exit",
                ));
            }
        };
        if !matches!(
            scope,
            se_proc::ScopeIdentity::LinuxPrepared { .. }
                | se_proc::ScopeIdentity::LinuxTracked { .. }
                | se_proc::ScopeIdentity::MacOsPrepared { .. }
                | se_proc::ScopeIdentity::MacOsTracked { .. }
        ) {
            return Err(SeError::invalid(
                "ownership release",
                "an uncontained tracked scope, never a kernel job or cgroup",
            ));
        }
        let marker = if let Some(marker) = existing.clone() {
            marker
        } else {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| error("release clock", e))?
                .as_nanos();
            let unknown = |reason: String| se_proc::RemainingScope {
                population: se_proc::Population::Unknown,
                known_live: Vec::new(),
                extent: se_proc::EnumerationExtent::Partial {
                    reason,
                    omitted: None,
                },
                observed_at_unix_ns: now,
            };
            let remaining = if work.process.is_some() {
                match self.exit_observation(work, deadline).await {
                    Ok(StopObservation::Complete(witness)) => {
                        self.finish(work, *witness, deadline).await?;
                        return super::control::fill_stopped(row, work, false);
                    }
                    Ok(StopObservation::Bounded(witness)) => witness.scope_exit.remaining,
                    Ok(StopObservation::Pending { scope, .. }) => scope.remaining,
                    Err(error) => unknown(format!(
                        "Owner release without a usable native observation: {error}"
                    )),
                }
            } else {
                unknown("Cold recovery acquired no signal or enumeration authority; population remains unknown.".into())
            };
            se_proc::UnwitnessedRelease {
                lifecycle: work.meta.lifecycle.clone(),
                generation: self.options.epoch.generation,
                revision: NonZeroU64::new(
                    previous
                        .revision
                        .value
                        .get()
                        .checked_add(1)
                        .ok_or_else(|| error("release revision", "exhausted"))?,
                )
                .ok_or_else(|| error("release revision", "zero"))?,
                scope,
                remaining,
                released_at_unix_ns: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| error("release clock", e))?
                    .as_nanos(),
            }
        };
        if !work.session_retired {
            self.retire_session(work, "owner released an unproved tracked process", deadline)
                .await?;
        }
        self.retire_files(work, deadline).await?;
        if existing.is_none() {
            checkpoint.checkpoint = CheckpointKind::Released {
                source,
                release: marker.clone(),
            };
            let mut released = identity.as_ref().clone();
            released.custody.record = se_proc::encode_checkpoint(&checkpoint)
                .map_err(|e| error("released custody codec", e))?;
            let event = self
                .change(
                    work,
                    "ownership-released",
                    released,
                    (ProcessState::StopUnproved, ProcessState::StopUnproved),
                    deadline,
                )
                .await?;
            work.last_stop_event = Some(event);
        }
        work.ownership_release = Some(marker.clone());
        if let Some(process) = work.process.clone() {
            let native = self.native.clone();
            self.store
                .pool
                .run_owned(deadline, move || {
                    native
                        .release_uncontained(&process, &marker)
                        .map_err(|e| error("native ownership release", e))
                })
                .await?;
        }
        work.released = true;
        work.active = false;
        work.binding = None;
        work.process = None;
        self.fill_release(row, work, deadline).await
    }
    pub(super) async fn fill_release(
        &self,
        row: &mut AgentStopResult,
        work: &Work,
        deadline: &Deadline,
    ) -> Result<()> {
        let marker = work.ownership_release.as_ref().ok_or_else(|| {
            se_core::scope::unreadable(
                "ownership release receipt",
                "the durable release marker is unavailable",
            )
        })?;
        row.result = "ownership-released".into();
        row.event_id = work.last_stop_event.clone();
        row.method = None;
        row.population = match marker.remaining.population {
            se_proc::Population::Empty => "empty",
            se_proc::Population::Populated => "populated",
            se_proc::Population::Unknown => "unknown",
        }
        .into();
        row.population_reason=Some("Ownership was explicitly released without proving closure; deliberate group escapes remain outside the tracked bound.".into());
        row.enumeration = match marker.remaining.extent {
            se_proc::EnumerationExtent::Complete => "complete",
            se_proc::EnumerationExtent::Partial { .. } => "best-effort",
            se_proc::EnumerationExtent::NotRequested => "unavailable",
        }
        .into();
        let mut diagnostics = Vec::new();
        for identity in marker.remaining.known_live.clone() {
            let at = deadline.at();
            match self
                .store
                .pool
                .run_owned(deadline, move || super::launch_util::view(&identity, at))
                .await
            {
                Ok(view) => diagnostics.push(view),
                Err(failure) => {
                    row.enumeration = "unavailable".into();
                    row.population_reason = Some(format!(
                        "Release retains its original native diagnostics; display birth observation failed: {failure}"
                    ));
                }
            }
        }
        row.remaining = diagnostics.clone();
        let at = se_core::ops::receipt::timestamp(
            i64::try_from(marker.released_at_unix_ns / 1000)
                .map_err(|_| SeError::invalid("release time", "representable Unix microseconds"))?,
        )?;
        row.ownership_release = Some(OwnershipRelease {
            lifecycle: marker.lifecycle.clone(),
            generation: marker.generation.get(),
            revision: marker.revision.get(),
            scope: format!("{:?}", marker.scope),
            remaining: diagnostics,
            released_at: at,
        });
        row.witness = StopWitness {
            state: "unwitnessed".into(),
            method: None,
            observed_at: None,
            detail: Some("This is a human ownership release, not a process exit witness.".into()),
        };
        row.capture.flushed = work.capture_flushed;
        row.capture.last_event_id = work.last_capture.clone();
        row.resume.state = "unavailable".into();
        row.resume.reason = Some(
            "An unwitnessed process may still be running; a new launch must be explicit.".into(),
        );
        Ok(())
    }
}
