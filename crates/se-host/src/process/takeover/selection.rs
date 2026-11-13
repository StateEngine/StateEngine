//! Confirmation and replacement retain the complete admitted lifecycle selection.
use super::*;
use se_store::{ProcessIdentityRecord, ProjectionRecord};
use se_types::{Detail, Read, SeError, details};

pub(super) fn process_identity(record: &ProjectionRecord) -> Result<&ProcessIdentityRecord> {
    match &record.current.body {
        EventBody::ProcessRegistered { identity, .. }
        | EventBody::ProcessTransition { identity, .. } => Ok(identity),
        _ => Err(error("takeover selection", "wrong process record kind")),
    }
}

fn sessions(plan: &LaunchPlan) -> Vec<se_types::SessionId> {
    plan.control
        .sessions
        .iter()
        .filter_map(|head| match &head.current.body {
            EventBody::SessionPrepared { session, .. }
            | EventBody::SessionActivated { session, .. } => Some(session.clone()),
            _ => None,
        })
        .collect()
}

fn confirmation(plan: &LaunchPlan, reason: String) -> Result<SeError> {
    Ok(SeError::new(Detail::LaunchConfirmationRequired(details::LaunchConfirmationRequired {
        subject: plan.agent.name.clone(), reason,
        lifecycles: plan.control.processes.iter().map(|head| process_identity(head).map(|identity| identity.record.clone())).collect::<Result<Vec<_>>>()?,
        sessions: sessions(plan),
        next_step: "Run this launch with --force to stop the listed sessions and all their managed jobs before relaunching. An interactive owner terminal asks for confirmation; scripts and agents must supply --force.".into(),
    })))
}

impl LaunchCoordinator {
    pub(super) fn require_force_selection(&self, plan: &LaunchPlan) -> Result<()> {
        let Some(selection) = &plan.input.force_selection else {
            return Ok(());
        };
        let mut expected = selection.lifecycles.clone();
        let mut current = plan
            .control
            .processes
            .iter()
            .map(|head| process_identity(head).map(|identity| identity.record.clone()))
            .collect::<Result<Vec<_>>>()?;
        expected.sort();
        current.sort();
        let mut expected_sessions = selection.sessions.clone();
        let mut current_sessions = sessions(plan);
        expected_sessions.sort();
        current_sessions.sort();
        if expected != current || expected_sessions != current_sessions {
            return Err(confirmation(plan, "The sessions or managed lifecycles changed after the displayed inventory. No process was stopped; inspect the current selection and confirm again.".into())?);
        }
        Ok(())
    }

    pub(super) async fn confirm_relaunch(
        self: &Arc<Self>,
        plan: &LaunchPlan,
        admission: &Admission,
        deadline: &Deadline,
    ) -> SeError {
        let mut observed = Vec::new();
        for record in &plan.control.processes {
            let identity = match process_identity(record) {
                Ok(identity) => identity,
                Err(failure) => {
                    observed.push(failure.to_string());
                    continue;
                }
            };
            let mut selected = plan.clone();
            selected.control.processes = vec![record.clone()];
            selected.control.latest_process = Read::Present {
                value: record.clone(),
            };
            let jobs = match self
                .inspect_takeover(&selected, admission, deadline, false)
                .await
            {
                Ok(report) => format!(
                    "{} scoped jobs: {}. Scope: {}",
                    report.jobs_remaining.len(),
                    job_names(&report.jobs_remaining),
                    report.scope
                ),
                Err(failure) => format!(
                    "job inventory unavailable: {failure}; this is not an empty-job observation"
                ),
            };
            let root = match &identity.instance {
                se_store::RecordedIdentity::Present(root) => format!(
                    "recorded root PID {} / executable {:?}",
                    root.fields().pid,
                    root.fields()
                        .executable
                        .to_local()
                        .map(|path| path.display().to_string())
                        .unwrap_or_else(|failure| format!("unreadable path: {failure}"))
                ),
                se_store::RecordedIdentity::Absent { reason } => {
                    format!("root identity absent: {}", reason.escape_debug())
                }
                se_store::RecordedIdentity::Unreadable { cause } => {
                    format!("root identity unreadable: {}", cause.escape_debug())
                }
            };
            observed.push(format!(
                "Lifecycle {} / session {:?} / {root}: {jobs}",
                identity.record, identity.session
            ));
        }
        for session_record in &plan.control.sessions {
            if let Some((session, conversation)) =
                se_core::ops::process_commit::embedded_session(session_record)
            {
                let service = if matches!(
                    session_record.original.as_deref().map(|event| &event.body),
                    Some(EventBody::SessionPrepared {
                        surface: Some(se_store::SessionSurface::Observed),
                        ..
                    })
                ) {
                    "user-owned provider"
                } else {
                    "externally owned SE Code service"
                };
                observed.push(format!("External binding {session}: {service} for conversation {}. --force retires only this engine binding; jobs in that provider are not stopped.", conversation.escape_debug()));
            }
        }
        if observed.is_empty() {
            observed.push("The complete control inventory has active session bindings without an unreleased native lifecycle; their retained cleanup must finish before replacement.".into());
        }
        confirmation(
            plan,
            format!(
                "{} active session bindings; {} managed lifecycles. {} No process was stopped.",
                plan.control.sessions.len(),
                plan.control.processes.len(),
                observed.join("\n")
            ),
        )
        .unwrap_or_else(|failure| failure)
    }

    pub(in crate::process) async fn preflight_relaunch(
        &self,
        plan: &mut LaunchPlan,
        admission: &Admission,
        deadline: &Deadline,
    ) -> Result<()> {
        plan.input.require_launch_mode(plan.profile.provider)?;
        if plan.replayed {
            return Ok(());
        }
        if plan.profile.provider == se_store::Provider::SeCode {
            self.preflight_secode(plan, deadline).await?;
        }
        if plan.profile.provider == se_store::Provider::Acp {
            self.preflight_acp(plan, admission, deadline).await?;
        }
        if let Err(failure) = self.check_resume_source(plan, admission, deadline).await {
            if !plan.input.override_live {
                return Err(failure);
            }
            plan.start_new_conversation(format!("Forced relaunch preserved the previous history and starts a new conversation because its saved source could not be resumed: {failure}"));
        }
        Ok(())
    }
}

pub(super) fn combine_reports(mut reports: Vec<TakeoverReport>) -> Result<TakeoverReport> {
    if reports.is_empty() {
        return Err(error(
            "takeover session cleanup",
            "No retained native lifecycle could close the active session binding; no successor was launched",
        ));
    }
    let mut first = reports.remove(0);
    if !reports.is_empty() {
        first.previous_sessions.push(first.previous_session.clone());
    }
    for report in reports {
        first.previous_sessions.push(report.previous_session);
        first.new_conversation |= report.new_conversation;
        first.external_services.extend(report.external_services);
        first.inventory_failure = match (first.inventory_failure.take(), report.inventory_failure) {
            (Some(first), Some(next)) => Some(format!("{first}; {next}")),
            (first, next) => first.or(next),
        };
        first.jobs_stopped.extend(report.jobs_stopped);
        first.jobs_remaining.extend(report.jobs_remaining);
        first.jobs_unproved.extend(report.jobs_unproved);
        first.witness.push_str("; ");
        first.witness.push_str(&report.witness);
    }
    first.jobs_stopped.sort_by_key(|job| job.pid);
    first.jobs_remaining.sort_by_key(|job| job.pid);
    Ok(first)
}
