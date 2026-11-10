//! A live launch never silently stops work. Inspection precedes even credential
//! revocation; explicit takeover reuses native stop, capture and outside witness.
use super::*;
use crate::client::lease::Deadline;
use se_core::ops::{
    AnyOutput, LaunchReply,
    agent_launch::{LaunchPlan, TakeoverJob, TakeoverReport},
};
use se_store::{Admission, EventBody};
use se_types::{Result, SeError};
use sha2::Digest;
use std::sync::atomic::Ordering;
mod replacement;
mod selection;
type Stopped =
    Arc<tokio::sync::Mutex<std::collections::BTreeMap<se_types::LifecycleId, TakeoverReport>>>;
use selection::{combine_reports, process_identity};

impl LaunchCoordinator {
    pub async fn launch(
        self: &Arc<Self>,
        mut plan: LaunchPlan,
        admission: Admission,
        deadline: &Deadline,
    ) -> Result<LaunchReply> {
        self.harness_for(plan.profile.provider)?;
        if !plan.replayed {
            self.require_force_selection(&plan)?;
        }
        if plan.replayed || (plan.control.processes.is_empty() && plan.control.sessions.is_empty())
        {
            self.preflight_relaunch(&mut plan, &admission, deadline)
                .await?;
            return self.launch_prepared(plan, admission, deadline, None).await;
        }
        let expired_window = matches!(&plan.control.latest_session, se_types::Read::Present { value }
            if se_core::ops::agent_launch::retryable_attended_setup(value));
        if !plan.input.override_live && !expired_window {
            return Err(self.confirm_relaunch(&plan, &admission, deadline).await);
        }
        self.preflight_relaunch(&mut plan, &admission, deadline)
            .await?;
        let key = format!(
            "takeover/{:?}/{:?}/{}",
            admission.scope, admission.actor, plan.input.idempotency_key
        );
        let intent = sha2::Sha256::digest(
            serde_json::to_vec(&serde_json::json!({
                "operation": "launch.takeover", "launch": plan.input.intent(&plan.agent.id)?
            }))
            .map_err(|e| error("takeover intent", e))?,
        )
        .into();
        let coordinator = Arc::downgrade(self);
        // Each original lifecycle has its own retained stop result. A retry
        // cannot stop a successor or repeat already achieved cleanup.
        let stopped = Arc::new(tokio::sync::Mutex::new(std::collections::BTreeMap::new()));
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
                    coordinator
                        .replace_selected(plan, admission, &deadline, stopped)
                        .await
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
        let expected = process_identity(&plan.control.processes[0])?.record.clone();
        let job = match self.find_lifecycle_job(&plan.project.id, &plan.agent.id, &expected)? {
            Some(job) => job,
            None if stop => self
                .cold_stop_job(&plan.control, &plan.project.id, deadline)
                .await?
                .ok_or_else(|| {
                    error(
                        "takeover custody",
                        "the recorded native lifecycle is unavailable",
                    )
                })?,
            None => {
                return Err(error(
                    "takeover custody",
                    "the recorded lifecycle is awaiting native recovery",
                ));
            }
        };
        if stop && plan.input.override_live {
            let key = se_core::ops::process_commit::phase_key(
                &plan.input.idempotency_key,
                &format!("takeover-startup/{expected}"),
            )?;
            self.interrupt_startup(&job, &key, admission.clone(), deadline)
                .await?;
        }
        let mut work = if stop {
            tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline.at()),
                job.state.lock(),
            )
            .await
            .map_err(|_| {
                error(
                    "takeover startup",
                    "the original launch is still joining; retry this --force request and key",
                )
            })?
        } else {
            job.control_state(deadline).await?
        };
        if work.meta.lifecycle != expected || work.ownership_release.is_some() {
            return Err(error(
                "takeover selection",
                "the selected lifecycle changed or its native ownership was released",
            ));
        }
        if stop
            && work.native_already_reconciled
            && !work.released
            && let Some(witness) = work.last_witness.clone()
        {
            self.finish(&mut work, witness, deadline).await?;
        }
        if work.released && work.last_witness.is_some() {
            return Ok(TakeoverReport {
                previous_session: work.meta.session.clone(),
                previous_sessions: Vec::new(),
                new_conversation: work.secode_service_lost || work.capture_failure.is_some(),
                scope: "the original retained native scope".into(),
                inventory_failure: None,
                external_services: Vec::new(),
                jobs_stopped: Vec::new(),
                jobs_remaining: Vec::new(),
                jobs_unproved: Vec::new(),
                witness: "original native scope already closed; retained session cleanup completed"
                    .into(),
            });
        }
        let native = self.native.clone();
        let process = work.process.clone().ok_or_else(|| {
            error(
                "takeover inspection",
                "no retained native process; reconcile its preparation first",
            )
        })?;
        let bound = deadline.at();
        let force = stop && plan.input.override_live;
        let (inspected, scope, inventory_failure) = self
            .store
            .pool
            .run_owned(deadline, move || {
                match inventory(&native, &process, bound) {
                    Ok((jobs, scope)) => Ok((jobs, scope, None)),
                    Err(failure) if force => Ok((
                        Vec::new(),
                        "the exact retained native scope; diagnostic job inventory is unavailable"
                            .into(),
                        Some(failure.to_string()),
                    )),
                    Err(failure) => Err(failure),
                }
            })
            .await?;
        let mut report = TakeoverReport {
            previous_session: work.meta.session.clone(),
            previous_sessions: Vec::new(),
            new_conversation: false,
            scope,
            inventory_failure,
            external_services: Vec::new(),
            jobs_stopped: Vec::new(),
            jobs_remaining: inspected.iter().map(|job| job.view.clone()).collect(),
            jobs_unproved: Vec::new(),
            witness: "not stopped".into(),
        };
        if stop {
            if !plan.input.override_live && !inspected.is_empty() {
                return Err(SeError::new(se_types::Detail::LaunchFailed(se_types::details::LaunchFailed {
                    subject: plan.agent.name.clone(),
                    reason: "Setup expired, but this window has running jobs. No process was stopped.".into(),
                    next_step: "Wait for those jobs to finish, or use --force to explicitly stop this managed scope and reconnect.".into(),
                })));
            }
            work.stop_key = Some(se_core::ops::process_commit::phase_key(
                &plan.input.idempotency_key,
                &format!("takeover-stop/{expected}"),
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
            if let Some(failure) = &work.capture_failure
                && !plan.input.override_live
            {
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
            let (stopped, remaining, unproved) = self.store.pool.run_owned(deadline, move || {
                let mut stopped = Vec::new();
                let mut remaining = Vec::new();
                let mut unproved = Vec::new();
                for job in inspected {
                    let read = match se_proc::read_process_until(job.identity.machine.clone(), job.identity.pid, bound) {
                        Ok(read) => read,
                        Err(cause) if force => {
                            let mut view = job.view;
                            view.command = format!("{} (exit observation unreadable: {cause:?})", view.command);
                            unproved.push(view);
                            continue;
                        }
                        Err(cause) => return Err(error("takeover job exit unreadable", format!("PID {}: {cause:?}; owned scope already stopped; individual job exit unproved; no successor launched", job.identity.pid.0))),
                    };
                    match read {
                        se_proc::ProcessRead::Present(live) if live.identity.boot == job.identity.boot && live.identity.start == job.identity.start
                            && matches!(live.state, se_proc::NativeState::Running | se_proc::NativeState::Stopped) => remaining.push(job.view),
                        _ => stopped.push(job.view),
                    }
                }
                Ok((stopped, remaining, unproved))
            }).await?;
            report.jobs_stopped = stopped;
            report.jobs_remaining = remaining;
            report.jobs_unproved = unproved;
            report.new_conversation = work.secode_service_lost || work.capture_failure.is_some();
            report.witness = match &work.capture_failure {
                Some(failure) => format!("native root exit and empty owned scope witnessed; session cleanup completed; final capture unavailable: {}", failure.message()),
                None => "native root exit and empty owned scope witnessed; capture and lifecycle cleanup completed".into(),
            };
        }
        Ok(report)
    }
}

fn job_names(jobs: &[TakeoverJob]) -> String {
    jobs.iter()
        .map(|job| format!("PID {}: {}", job.pid, job.command.escape_debug()))
        .collect::<Vec<_>>()
        .join("; ")
}

fn successor_failure(report: &TakeoverReport, failure: SeError) -> SeError {
    // A retained successor waiting for its provider is a known pending launch,
    // not lost stop/capture evidence or an unreadable takeover outcome.
    if failure.code() == se_types::Code::LaunchReadinessTimeout {
        return failure;
    }
    se_core::scope::unreadable(
        "takeover incomplete",
        &format!(
            "previous session {} was retired; observed job exits: {}; witness: {}; jobs still running: {:?}; individual exits unproved: {:?}; external service jobs not stopped: {:?}; inventory unavailable: {:?}. Successor or cleanup failed: {failure}",
            report.previous_session,
            job_names(&report.jobs_stopped),
            report.witness,
            report.jobs_remaining,
            report.jobs_unproved,
            report.external_services,
            report.inventory_failure
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
                "unreadable or incomplete: population={:?}, extent={:?}; no diagnostic job count is available",
                remaining.population, remaining.extent
            ),
        ));
    }
    let mut jobs = Vec::new();
    let mut command_bytes = 0_usize;
    let mut members = remaining.known_live.clone();
    #[cfg(any(target_os = "linux", windows))]
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
        #[cfg(any(target_os = "linux", windows))]
        if viewer.as_ref() == Some(member) {
            continue;
        }
        let command = se_proc::read_process_command(member, bound).map_err(|cause| {
            error(
                "takeover job command unreadable",
                format!(
                    "PID {}: {cause:?}; the job command is unreadable",
                    member.pid.0
                ),
            )
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
