//! Recovery that a reboot may have decided: a lifecycle whose recorded boot has
//! ended is proven exited by the reboot itself, and launch closes such a
//! lifecycle before starting its successor. Declared from `process`, whose
//! private custody state it reads.
use super::{takeover::process_identity, *};
use crate::client::lease::Deadline;
use se_core::ops::{agent_launch::LaunchPlan, process_commit};
use se_proc::{CheckpointKind, CheckpointSource, ProcessRuntime, RecoveryOutcome, RecoverySource};
use se_store::{Actor, OwnerGuardProcess, ProcessState};
use se_types::Result;
use std::sync::atomic::Ordering;

impl LaunchCoordinator {
    pub(in crate::process) async fn observe_recovery(
        &self,
        checkpoint: se_proc::Checkpoint,
        retained: &OwnerGuardProcess,
        deadline: &Deadline,
    ) -> Result<RecoveryOutcome> {
        let recorded_exit = match (retained.state, &checkpoint.checkpoint) {
            (ProcessState::Exited, CheckpointKind::Exit { witness, .. }) => Some(witness.clone()),
            _ => None,
        };
        let source = recovery_source(&checkpoint, retained)?;
        let instance = match &retained.identity.instance {
            se_store::RecordedIdentity::Present(instance) => Some(instance.clone()),
            _ => None,
        };
        let machine = self.owner.machine.clone();
        let native = self.native.clone();
        let generation = self.options.epoch.generation;
        self.store
            .pool
            .run_owned(deadline, move || {
                if let Some(instance) = instance {
                    let current = se_proc::observe_reboot_boot(machine)
                        .map_err(|e| error("native reboot identity", e))?;
                    match se_proc::prove_reboot(&checkpoint, &instance, &current) {
                        se_proc::RebootProof::Proven(proof) => {
                            if let Some(witness) = recorded_exit {
                                return Ok(RecoveryOutcome::Exited(Box::new(witness)));
                            }
                            let witness = native
                                .witness_reboot(&proof)
                                .map_err(|e| error("native reboot witness", e))?;
                            return Ok(RecoveryOutcome::Exited(Box::new(witness)));
                        }
                        se_proc::RebootProof::NotProven => {}
                        se_proc::RebootProof::Unreadable(reason) => {
                            return Err(error("reboot proof", reason));
                        }
                    }
                }
                let plan = native
                    .plan_recovery(source)
                    .map_err(|e| error("native recovery plan", e))?;
                native
                    .recover(plan, generation)
                    .map_err(|e| error("native custody recovery", e))
            })
            .await
    }

    pub(in crate::process) async fn finish_rebooted_launch(
        &self,
        plan: &LaunchPlan,
        deadline: &Deadline,
    ) -> Result<bool> {
        let pending = !plan.control.processes.is_empty() || !plan.control.sessions.is_empty();
        let records = if plan.control.processes.is_empty() {
            match &plan.control.latest_process {
                se_types::Read::Present { value } => std::slice::from_ref(value),
                _ => &[],
            }
        } else {
            plan.control.processes.as_slice()
        };
        let mut closed = false;
        for record in records {
            let identity = process_identity(record)?;
            let Some(job) = self
                .find_lifecycle_job(&plan.project.id, &plan.agent.id, &identity.record)?
                .filter(|job| {
                    job.ended_by_reboot && (pending || !job.settled.load(Ordering::Acquire))
                })
            else {
                continue;
            };
            let mut work = crate::runtime::pool::within(deadline, job.state.lock()).await?;
            let Some(witness) = work.last_witness.clone().filter(|w| w.ended_by_reboot()) else {
                continue;
            };
            if !work.released {
                work.admission = work.cleanup_admission.clone();
                self.finish(&mut work, witness, deadline).await?;
                if !job.settled.swap(true, Ordering::AcqRel) {
                    self.activity
                        .send_modify(|count| *count = count.saturating_sub(1));
                }
            }
            closed = true;
        }
        Ok(closed)
    }
}

pub(in crate::process) fn recovery_method(witness: &se_proc::StopWitness) -> &'static str {
    if witness.ended_by_reboot() {
        process_commit::ENDED_BY_REBOOT
    } else {
        "native-reconciliation"
    }
}
fn recovery_source(
    checkpoint: &se_proc::Checkpoint,
    retained: &OwnerGuardProcess,
) -> Result<RecoverySource> {
    if checkpoint.lifecycle != retained.identity.record
        || checkpoint.session != retained.identity.session
        || !matches!((&checkpoint.principal, &retained.identity.principal), (se_proc::CheckpointPrincipal::Agent(a),Actor::Agent(b)) if a==b)
    {
        return Err(error(
            "startup custody codec",
            "principal/session/lifecycle differs from protected index",
        ));
    }
    Ok(match &checkpoint.checkpoint {
        CheckpointKind::Reservation(v) => RecoverySource::Reservation(Box::new(v.clone())),
        CheckpointKind::Scope(v) => RecoverySource::Prepared(Box::new(v.clone())),
        CheckpointKind::Root(v) => RecoverySource::RootPrepared(Box::new(v.clone())),
        CheckpointKind::Process(v) => RecoverySource::Record(Box::new(v.clone())),
        CheckpointKind::Exit { source, .. } => match source.as_ref() {
            CheckpointSource::Reservation(v) => RecoverySource::Reservation(Box::new(v.clone())),
            CheckpointSource::Scope(v) => RecoverySource::Prepared(Box::new(v.clone())),
            CheckpointSource::Root(v) => RecoverySource::RootPrepared(Box::new(v.clone())),
            CheckpointSource::Process(v) => RecoverySource::Record(Box::new(v.clone())),
        },
        _ => {
            return Err(error(
                "startup custody codec",
                "unsupported terminal or historical checkpoint",
            ));
        }
    })
}
