//! A live launch never silently stops work. Inspection precedes even credential
//! revocation; explicit takeover reuses native stop, capture and outside witness.
use super::*;
use crate::client::lease::Deadline;
use se_core::ops::{
    AnyOutput, LaunchResult,
    agent_launch::{LaunchPlan, TakeoverJob, TakeoverReport},
};
use se_store::{Admission, EventBody};
use se_types::{Result, SeError};
use sha2::Digest;
use std::sync::atomic::Ordering;

impl LaunchCoordinator {
    pub async fn launch(
        self: &Arc<Self>,
        plan: LaunchPlan,
        admission: Admission,
        deadline: &Deadline,
    ) -> Result<LaunchResult> {
        let expired_window = matches!(&plan.control.latest_session, se_types::Read::Present { value }
            if se_core::ops::agent_launch::retryable_attended_setup(value));
        if !plan.input.override_live && (plan.replayed || plan.control.processes.is_empty()) {
            return self.launch_prepared(plan, admission, deadline, None).await;
        }
        if !plan.input.override_live && plan.control.processes.len() != 1 {
            return Err(error(
                "takeover inventory",
                "multiple unreleased lifecycles; reconcile them before launch",
            ));
        }
        if !plan.input.override_live && !expired_window {
            // No effect is allowed on the refusal path, including revocation.
            let jobs = self
                .inspect_takeover(&plan, &admission, deadline, false)
                .await?;
            return Err(SeError::new(se_types::Detail::LaunchFailed(se_types::details::LaunchFailed {
                subject: "live launch".into(),
                reason: format!(
                    "the existing agent lifecycle must be stopped first; {} scoped jobs other than the harness: {}. No process was stopped. Scope bound: {}",
                    jobs.jobs_remaining.len(),
                    jobs.jobs_remaining
                        .iter()
                        .map(|job| format!("PID {}: {}", job.pid, job.command))
                        .collect::<Vec<_>>()
                        .join("; "),
                    jobs.scope
                ),
                next_step: "Wait for jobs to finish, run long jobs outside this managed scope, or retry launch with --override-live to stop the entire scope.".into(),
            })));
        }
        let key = format!(
            "takeover/{:?}/{:?}/{}",
            admission.scope, admission.actor, plan.input.idempotency_key
        );
        let serialized = serde_json::to_vec(&serde_json::json!({
            "operation": "launch.takeover", "launch": plan.input.intent(&plan.agent.id)?
        }))
        .map_err(|e| error("takeover intent", e))?;
        let intent = sha2::Sha256::digest(serialized).into();
        let coordinator = Arc::downgrade(self);
        // Retain achieved stop/capture across a disconnected waiter or failed
        // successor. A retry must never select and stop a newer lifecycle.
        let stopped = Arc::new(tokio::sync::Mutex::new(None::<TakeoverReport>));
        let output = self
            .supervise_control(key, intent, deadline, move |deadline| {
                let coordinator = coordinator.clone();
                let plan = plan.clone();
                let admission = admission.clone();
                let stopped = stopped.clone();
                async move {
                    let coordinator = coordinator
                        .upgrade()
                        .ok_or_else(|| error("takeover retry", "the original host retired"))?;
                    // Lookup of the retained control happens before this closure.
                    // A retry after stop must rejoin the original report even
                    // when the current store now has no live predecessor.
                    if plan.replayed || plan.control.processes.is_empty() {
                        return coordinator
                            .launch_prepared(plan, admission, &deadline, None)
                            .await
                            .map(AnyOutput::from);
                    }
                    if plan.control.processes.len() != 1 {
                        return Err(error(
                            "takeover inventory",
                            "multiple unreleased lifecycles; reconcile them before launch",
                        ));
                    }
                    let mut report = stopped.lock().await;
                    if report.is_none() {
                        *report = Some(
                            coordinator
                                .inspect_takeover(&plan, &admission, &deadline, true)
                                .await?,
                        );
                    }
                    let report = report.clone().ok_or_else(|| {
                        error(
                            "takeover receipt",
                            "the achieved stop report is unavailable",
                        )
                    })?;
                    let input = plan.input.clone();
                    let seed = plan.seed.clone();
                    let configuration = coordinator.options.configuration.clone();
                    let next = coordinator
                        .store
                        .read(admission.clone(), &deadline, move |cx| {
                            let mut facts = crate::runtime::start::allocate_facts()?;
                            facts.event = seed;
                            se_core::ops::process_plan::launch(
                                &se_core::dispatch::Kernel::new(facts)?,
                                input,
                                &configuration,
                                cx,
                            )
                        })
                        .await
                        .map_err(|failure| successor_failure(&report, failure))?;
                    coordinator
                        .launch_prepared(next, admission, &deadline, Some(report.clone()))
                        .await
                        .map_err(|failure| successor_failure(&report, failure))
                        .map(AnyOutput::from)
                }
            })
            .await?;
        match output {
            AnyOutput::AgentLaunch(value) => Ok(value.value),
            _ => Err(error(
                "takeover receipt",
                "the retained request has another operation",
            )),
        }
    }

    async fn inspect_takeover(
        self: &Arc<Self>,
        plan: &LaunchPlan,
        admission: &Admission,
        deadline: &Deadline,
        stop: bool,
    ) -> Result<TakeoverReport> {
        if stop
            && matches!(&admission.actor, se_store::Actor::Agent(agent) if agent == &plan.agent.id)
        {
            return Err(error(
                "self takeover",
                "use the owner's terminal to replace your own session; stopping it revokes the authority required to launch its successor",
            ));
        }
        let job = self.find_job(&plan.project.id, &plan.agent.id)?.ok_or_else(|| {
            error("takeover custody", "native inventory is unavailable, not empty; reconcile the recorded lifecycle before retrying; no process was stopped")
        })?;
        let mut work = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline.at()),
            job.state.lock(),
        )
        .await
        .map_err(|_| {
            error(
                "takeover inspection",
                "the existing lifecycle is busy; retry after it settles",
            )
        })?;
        let expected = match &plan.control.processes[0].current.body {
            EventBody::ProcessRegistered { identity, .. }
            | EventBody::ProcessTransition { identity, .. } => &identity.record,
            _ => return Err(error("takeover selection", "wrong process record kind")),
        };
        if &work.meta.lifecycle != expected || work.released || work.ownership_release.is_some() {
            return Err(error(
                "takeover selection",
                "the selected lifecycle changed; reread the target before retrying",
            ));
        }
        let native = self.native.clone();
        let process = work.process.clone().ok_or_else(|| {
            error(
                "takeover inspection",
                "no retained native process; reconcile its preparation first",
            )
        })?;
        let bound = deadline.at();
        let (inspected, scope) = self
            .store
            .pool
            .run_owned(deadline, move || inventory(&native, &process, bound))
            .await?;
        let mut report = TakeoverReport {
            previous_session: work.meta.session.clone(),
            scope,
            jobs_stopped: Vec::new(),
            jobs_remaining: inspected.iter().map(|job| job.view.clone()).collect(),
            witness: "not stopped".into(),
        };
        if stop {
            if !plan.input.override_live && !inspected.is_empty() {
                return Err(SeError::new(se_types::Detail::LaunchFailed(se_types::details::LaunchFailed {
                    subject: plan.agent.name.clone(),
                    reason: "Setup expired, but this window has running jobs. No process was stopped.".into(),
                    next_step: "Wait for those jobs to finish, or use --override-live to explicitly stop this managed scope and reconnect.".into(),
                })));
            }
            work.stop_key = Some(se_core::ops::process_commit::phase_key(
                &plan.input.idempotency_key,
                "takeover-stop",
            )?);
            work.admission = admission.clone();
            let witness = self.stop_native(&mut work, deadline).await.map_err(|failure| error("takeover stop incomplete", format!("selected jobs: {}; their stop outcome is unproved; inspect the original lifecycle before retrying: {failure}", job_names(&report.jobs_remaining))))?;
            work.last_witness = Some(witness.clone());
            report.witness = "native root exit and empty owned scope witnessed; capture and lifecycle cleanup pending".into();
            work.admission = work.cleanup_admission.clone();
            self.finish(&mut work, witness, deadline)
                .await
                .map_err(|failure| successor_failure(&report, failure))?;
            if !job.settled.swap(true, Ordering::AcqRel) {
                self.activity
                    .send_modify(|count| *count = count.saturating_sub(1));
            }
            if let Some(failure) = &work.capture_failure {
                return Err(successor_failure(
                    &report,
                    error(
                        "takeover capture",
                        format!(
                            "old process stopped but capture failed: {}; original transcript retained; inspect before relaunch",
                            failure.message()
                        ),
                    ),
                ));
            }
            let (stopped, remaining) = self.store.pool.run_owned(deadline, move || {
                let mut stopped = Vec::new();
                let mut remaining = Vec::new();
                for job in inspected {
                    let read = se_proc::read_process_until(job.identity.machine.clone(), job.identity.pid, bound)
                        .map_err(|cause| error("takeover job exit unreadable", format!("PID {}: {cause:?}; owned scope already stopped; individual job exit unproved; no successor launched", job.identity.pid.0)))?;
                    match read {
                        se_proc::ProcessRead::Present(live) if live.identity.boot == job.identity.boot && live.identity.start == job.identity.start
                            && matches!(live.state, se_proc::NativeState::Running | se_proc::NativeState::Stopped) => remaining.push(job.view),
                        _ => stopped.push(job.view),
                    }
                }
                Ok((stopped, remaining))
            }).await?;
            report.jobs_stopped = stopped;
            report.jobs_remaining = remaining;
            report.witness = "native root exit and empty owned scope witnessed; capture and lifecycle cleanup completed".into();
        }
        Ok(report)
    }
}

fn job_names(jobs: &[TakeoverJob]) -> String {
    jobs.iter()
        .map(|job| format!("PID {}: {}", job.pid, job.command))
        .collect::<Vec<_>>()
        .join("; ")
}

fn successor_failure(report: &TakeoverReport, failure: SeError) -> SeError {
    // A retained successor waiting for its provider is a known pending launch,
    // not lost stop/capture evidence or an unreadable takeover outcome.
    if failure.code() == se_types::Code::LaunchReadinessTimeout {
        return failure;
    }
    error(
        "takeover incomplete",
        format!(
            "previous session {} was stopped; observed scoped jobs stopped: {}; witness: {}; jobs not proven stopped: {:?}. Successor or cleanup failed (retain any unknown outcome named here): {failure}",
            report.previous_session,
            job_names(&report.jobs_stopped),
            report.witness,
            report.jobs_remaining
        ),
    )
}

/// Scope membership, native identity and command readability are independent
/// observations. None of the diagnostic PIDs becomes a signalling selector.
fn inventory(
    native: &se_proc::NativeProcessRuntime,
    process: &se_proc::OwnedProcess,
    bound: std::time::Instant,
) -> Result<(Vec<InspectedJob>, String)> {
    let observed = native
        .observe(process)
        .map_err(|cause| error("takeover job inventory", cause))?;
    let remaining = &observed.scope.remaining;
    if remaining.population == se_proc::Population::Unknown
        || !matches!(remaining.extent, se_proc::EnumerationExtent::Complete)
    {
        return Err(error(
            "takeover job inventory",
            format!(
                "unreadable or incomplete: population={:?}, extent={:?}; no process stopped; repair observation before retrying, even with --override-live",
                remaining.population, remaining.extent
            ),
        ));
    }
    let mut jobs = Vec::new();
    let mut command_bytes = 0_usize;
    let mut members = remaining.known_live.clone();
    #[cfg(target_os = "linux")]
    let viewer = native
        .window_viewer(process)
        .map_err(|cause| error("takeover terminal inventory", cause))?;
    #[cfg(target_os = "linux")]
    members.extend(
        se_proc::read_process_descendants(&observed.record.root, bound)
            .map_err(|cause| error("takeover descendant inventory", cause))?,
    );
    members.sort_by_key(|member| member.pid.0);
    members.dedup();
    for member in &members {
        if member == &observed.record.root {
            continue;
        }
        #[cfg(target_os = "linux")]
        if viewer.as_ref() == Some(member) {
            continue;
        }
        let command = se_proc::read_process_command(member, bound).map_err(|cause| {
            error("takeover job command unreadable", format!(
                "PID {}: {cause:?}; no process was stopped; repair command access before retrying; --override-live cannot treat unreadable as empty",
                member.pid.0
            ))
        })?;
        if let Some(command) = command {
            command_bytes += command.len();
            if command_bytes > 256 * 1024 {
                return Err(error(
                    "takeover job inventory",
                    "command inventory exceeds 256 KiB; no process was stopped; inspect the jobs outside this bounded launch report before stopping explicitly",
                ));
            }
            jobs.push(InspectedJob {
                identity: member.clone(),
                view: TakeoverJob {
                    pid: member.pid.0,
                    command,
                },
            });
        }
    }
    jobs.sort_by_key(|job| job.view.pid);
    let scope = if cfg!(windows) {
        "Windows job members; commands show executable paths only; explicit breakaway is outside the job"
    } else {
        "Linux tracked group plus currently attributable descendants; already reparented escaped jobs cannot be attributed or proven absent"
    };
    Ok((jobs, scope.to_owned()))
}

struct InspectedJob {
    identity: se_proc::ProcessIdentity,
    view: TakeoverJob,
}
