//! Stop requests keep their exact admitted selection and continue after caller
//! disconnect. One target's failure cannot suppress independent target results.
use super::supervisor::Job;
use super::*;
use crate::client::lease::Deadline;
use se_core::ops::{
    StopResult,
    agent_stop::{AgentStopResult, StopCapture, StopResume, StopWitness},
    stop_plan::{ControlAgent, StopPlan},
};
use se_store::{Admission, EventBody, Snapshot};
use se_types::{IdempotencyKey, Result, SeError};
use sha2::{Digest, Sha256};
use std::sync::atomic::Ordering;
impl LaunchCoordinator {
    pub async fn stop(
        self: &Arc<Self>,
        plan: StopPlan,
        admission: Admission,
        deadline: &Deadline,
    ) -> Result<StopResult> {
        let key = format!(
            "{:?}/{:?}/{}",
            admission.scope, admission.actor, plan.input.idempotency_key
        );
        let intent=Sha256::digest(serde_json::to_vec(&serde_json::json!({"operation":"agent.stop","input":plan.input,"selector":plan.input.owner_agent,"all":plan.input.all,"release":plan.input.release,"scope":format!("{:?}",admission.scope)})).map_err(|e|error("stop request intent",e))?).into();
        let coordinator = Arc::downgrade(self);
        match self
            .supervise_control(key, intent, deadline, move |deadline| {
                let coordinator = coordinator.clone();
                let plan = plan.clone();
                let admission = admission.clone();
                async move {
                    coordinator
                        .upgrade()
                        .ok_or_else(|| error("stop retry", "the original host has retired"))?
                        .stop_selected(plan, admission, &deadline)
                        .await
                        .map(se_core::ops::AnyOutput::from)
                }
            })
            .await?
        {
            se_core::ops::AnyOutput::AgentStop(value) => Ok(value.value),
            _ => Err(se_core::scope::unreadable(
                "stop receipt",
                "the retained request belongs to another operation",
            )),
        }
    }
    pub(super) async fn stop_selected(
        self: &Arc<Self>,
        mut plan: StopPlan,
        admission: Admission,
        deadline: &Deadline,
    ) -> Result<StopResult> {
        let mut selection_failures = Vec::new();
        if plan.input.all && plan.targets.is_empty() {
            for project in plan.projects {
                let mut admitted = admission.clone();
                admitted.scope = se_store::Scope::Project(project.id.clone());
                let project_id = project.id.clone();
                let result = self
                    .store
                    .read(admitted, deadline, move |cx| {
                        se_core::ops::stop_plan::agents(project, cx)
                    })
                    .await;
                match result {
                    Ok(mut targets) => plan.targets.append(&mut targets),
                    Err(error) => selection_failures.push(format!("project {project_id}: {error}")),
                }
            }
        }
        let mut stops = Vec::with_capacity(plan.targets.len());
        for target in plan.targets {
            let mut admitted = admission.clone();
            admitted.scope = se_store::Scope::Project(target.target.project.id.clone());
            stops.push(
                self.stop_target(
                    target,
                    &plan.input.idempotency_key,
                    plan.input.release,
                    admitted,
                    deadline,
                )
                .await,
            );
        }
        let complete = selection_failures.is_empty()
            && stops
                .iter()
                .all(|row| matches!(row.result.as_str(), "stopped" | "already-stopped"));
        if plan.input.all {
            return Ok(StopResult {
                idempotency_key: plan.input.idempotency_key,
                receipt: "seat-stop/v1".into(),
                scope: "all".into(),
                result: if complete { "stopped" } else { "partial" }.into(),
                complete,
                event_id: None,
                target: None,
                method: None,
                witness: None,
                population: if selection_failures.is_empty() {
                    None
                } else {
                    Some("unknown".into())
                },
                population_reason: if selection_failures.is_empty() {
                    None
                } else {
                    Some(selection_failures.join("; "))
                },
                ownership_release: None,
                remaining: None,
                enumeration: None,
                capture: None,
                resume: None,
                stops: Some(stops),
            });
        }
        let row = stops
            .pop()
            .ok_or_else(|| SeError::invalid("stop selection", "one resolved target"))?;
        Ok(StopResult {
            idempotency_key: plan.input.idempotency_key,
            receipt: "seat-stop/v1".into(),
            scope: "agent".into(),
            result: row.result,
            complete,
            event_id: row.event_id,
            target: Some(row.target),
            method: row.method,
            witness: Some(row.witness),
            population: Some(row.population),
            population_reason: row.population_reason,
            ownership_release: row.ownership_release,
            remaining: Some(row.remaining),
            enumeration: Some(row.enumeration),
            capture: Some(row.capture),
            resume: Some(row.resume),
            stops: None,
        })
    }
    async fn stop_target(
        self: &Arc<Self>,
        target: ControlAgent,
        key: &IdempotencyKey,
        release: bool,
        admission: Admission,
        deadline: &Deadline,
    ) -> AgentStopResult {
        let retained = self.find_job(&target.target.project.id, &target.target.agent.id);
        let mut row = empty_row(target, &self.options.home);
        let result=async{
            // A refused target becomes one result row; it cannot suppress the
            // independent targets selected by --all.
            let agent=row.target.agent.id.clone();
            let current=self.store.read(admission.clone(),deadline,move |cx| se_core::scope::require_present(cx.read.control_target(agent).map_err(|e|se_core::store_error::store_error(&e))?,"current stop control","Restore the current create grant or use the owner's terminal.")).await?;
            if current.processes.len()>1 {return Err(error("stop lifecycle inventory","more than one unreleased lifecycle belongs to this agent; retain the full inventory for owner reconciliation"));}
            let job=match retained? {Some(job)=>Some(job),None=>self.cold_stop_job(&current,&row.target.project.id,deadline).await?};
            let Some(job)=job else {
                if current.processes.is_empty() && current.sessions.is_empty() && matches!(current.latest_process,se_types::Read::Absent {..}) {
                    row.result="already-stopped".into();row.population="empty".into();row.enumeration="not-applicable".into();
                    row.witness=StopWitness {state:"witnessed".into(),method:Some("not-applicable".into()),observed_at:Some(se_core::ops::receipt::timestamp(crate::runtime::start::now_unix_micros()?)?),detail:Some("The complete admitted control snapshot contains no recorded managed lifecycle or live session.".into())};
                    return Ok(());
                }
                return Err(se_core::scope::unreadable("cold stop custody","this host has no retained native reference; protected-record recovery is required before claiming an exit"));
            };
            if !release { self.interrupt_startup(&job,key,admission.clone(),deadline).await?; }
            let mut work=tokio::time::timeout_at(tokio::time::Instant::from_std(deadline.at()),job.state.lock()).await.map_err(|_|se_core::scope::unreadable("stop preparation","the retained launch is still settling; retry the original stop key"))?;
            row.target.session_id=Some(work.meta.session.clone());row.target.launch_id=Some(se_proc::session_launch_id(&work.meta.session).map_err(|e|error("stop launch identity",e))?);
            row.target.process = work.process_view.clone();
            if work.ownership_release.is_some(){self.fill_release(&mut row,&work,deadline).await?;return Ok(());}
            if release {
                work.stop_key=Some(key.clone());
                work.admission=admission;
                self.release_target(&mut work,&mut row,deadline).await?;
                if !job.settled.swap(true,Ordering::AcqRel){self.activity.send_modify(|count|*count=count.saturating_sub(1));}
                return Ok(());
            }
            if work.released {
                if let Err(error) = self.flush_capture(&mut work, deadline).await
                    && work.capture_failure.is_none()
                {
                    return Err(error);
                }
                self.retire_capture(&mut work, deadline).await?;
                fill_stopped(&mut row,&work,true)?;
                return Ok(());
            }
            work.stop_key=Some(key.clone());
            work.admission=admission;
            let witness=self.stop_native(&mut work,deadline).await?;
            work.last_witness=Some(witness.clone());
            work.admission=work.cleanup_admission.clone();
            self.finish(&mut work,witness,deadline).await?;
            if !job.settled.swap(true,Ordering::AcqRel){self.activity.send_modify(|count|*count=count.saturating_sub(1));}
            fill_stopped(&mut row,&work,false)?;Ok(())
        }.await;
        if let Err(error) = result {
            row.witness.detail = Some(error.to_string());
            row.population_reason=Some("Native closure or retained cleanup is incomplete; an empty diagnostic list proves nothing.".into());
        }
        row
    }
    pub(super) fn find_job(
        &self,
        project: &se_types::ProjectId,
        agent: &se_types::AgentId,
    ) -> Result<Option<Arc<Job>>> {
        let jobs =
            self.jobs.0.lock().map_err(|_| {
                SeError::invalid("process supervisors", "unpoisoned retained registry")
            })?;
        Ok(jobs
            .values()
            .filter(|job| &job.target.0 == project && &job.target.1 == agent)
            .max_by(|a, b| {
                (!a.settled.load(Ordering::Acquire), a.lifecycle.as_str())
                    .cmp(&(!b.settled.load(Ordering::Acquire), b.lifecycle.as_str()))
            })
            .cloned())
    }
}
fn empty_row(target: ControlAgent, home: &std::path::Path) -> AgentStopResult {
    let latest = match &target.control.latest_session {
        se_types::Read::Present { value } => Some(value),
        _ => None,
    };
    let window = target.control.sessions.iter().chain(latest).any(|session| {
        matches!(
            &session.original.as_deref().unwrap_or(&session.current).body,
            EventBody::SessionPrepared {
                surface: Some(se_store::SessionSurface::Window),
                ..
            }
        )
    });
    let profile = match target.control.profile {
        se_types::Read::Present { value } => match value.current.body {
            EventBody::ProfileSaved { profile, .. } => Some(profile),
            _ => None,
        },
        _ => None,
    };
    let resume = se_core::ops::AgentCommand::launch_in_home(
        &target.target.agent.id,
        home,
        &target.target.project.id,
        false,
    )
    .map(|command| command.with_detach(!window));
    AgentStopResult {
        resume: StopResume {
            state: "unavailable".into(),
            reason: Some(if resume.is_none() {
                se_core::ops::AgentCommand::HOME_UNAVAILABLE.into()
            } else {
                "No original conversation has been proven by this stop.".into()
            }),
            conversation_id: None,
            provider: target.target.provider,
            model: profile.and_then(|p| p.model),
            command: resume
                .as_ref()
                .map(|value| value.command.clone())
                .unwrap_or_default(),
            argv: resume.map(|value| value.argv).unwrap_or_default(),
        },
        target: target.target,
        result: "unwitnessed".into(),
        event_id: None,
        method: None,
        witness: StopWitness {
            state: "unwitnessed".into(),
            method: None,
            observed_at: None,
            detail: None,
        },
        population: "unknown".into(),
        population_reason: None,
        ownership_release: None,
        remaining: Vec::new(),
        enumeration: "unavailable".into(),
        capture: StopCapture {
            flushed: false,
            last_event_id: None,
        },
    }
}
pub(super) fn fill_stopped(
    row: &mut AgentStopResult,
    work: &super::launch::Work,
    already: bool,
) -> Result<()> {
    let witness = work.last_witness.as_ref().ok_or_else(|| {
        se_core::scope::unreadable("stop receipt", "no retained outside exit witness")
    })?;
    row.result = if already {
        "already-stopped"
    } else {
        "stopped"
    }
    .into();
    row.event_id = if already {
        None
    } else {
        work.last_stop_event.clone()
    };
    row.method = if already {
        None
    } else {
        work.stop_method.clone()
    };
    row.witness = StopWitness {
        state: "witnessed".into(),
        method: Some(
            match witness.scope_exit.exit_basis {
                Some(se_proc::ScopeExitBasis::RemovedPinnedLinuxCgroup) => {
                    "pidfd-exit+cgroup-removed"
                }
                _ => {
                    if cfg!(windows) {
                        "job-empty"
                    } else {
                        "start-identity-exit+pgid-empty"
                    }
                }
            }
            .into(),
        ),
        observed_at: Some(se_core::ops::receipt::timestamp(
            i64::try_from(witness.observed_at_unix_ns / 1000).map_err(|_| {
                SeError::invalid("exit witness time", "representable Unix microseconds")
            })?,
        )?),
        detail: Some(format!(
            "scope={:?}; guarantee={:?}; root={:?}",
            witness.scope, witness.guarantee, witness.root
        )),
    };
    row.population = "empty".into();
    row.population_reason = None;
    row.remaining.clear();
    row.enumeration = match witness.scope_exit.remaining.extent {
        se_proc::EnumerationExtent::Complete => "complete",
        _ => "best-effort",
    }
    .into();
    if let Some(error) = &work.stop_failure {
        row.witness.detail = Some(format!(
            "{}; graceful stop failed before the native fallback: {}",
            row.witness.detail.as_deref().unwrap_or(""),
            SeError {
                body: error.clone(),
                cause: None
            }
        ));
    }
    row.capture = StopCapture {
        flushed: work.capture_flushed,
        last_event_id: work.last_capture.clone(),
    };
    if let Some(failure) = &work.capture_failure {
        row.result = "capture-incomplete".into();
        row.resume.state = "capture-incomplete".into();
        row.resume.reason = Some(format!(
            "Native exit is witnessed; capture failed: {}. Restore the original transcript and retry stop to capture its pending records, then resume the saved conversation; --new remains available for a fresh conversation.",
            failure.message()
        ));
        row.resume.conversation_id = None;
        row.resume.argv.clear();
        row.resume.command.clear();
        return Ok(());
    }
    row.resume.model = work.meta.model.clone();
    match (&work.meta.conversation, work.activated) {
        (se_types::Read::Present { value }, true) if !row.resume.argv.is_empty() => {
            row.resume.state = "ready".into();
            row.resume.reason = None;
            row.resume.conversation_id = Some(value.to_string());
        }
        _ if row.resume.argv.is_empty() => {
            row.resume.state = "unavailable".into();
            row.resume.reason = Some(se_core::ops::AgentCommand::HOME_UNAVAILABLE.into());
            row.resume.conversation_id = None;
        }
        _ => {
            row.resume.state = "unavailable".into();
            row.resume.reason=Some("The launch never activated a proven original conversation; use --new for a fresh attempt.".into());
            row.resume.conversation_id = None;
        }
    }
    Ok(())
}
