//! Stop and clean each selected project independently, then commit its
//! tombstone. The outside CLI owns standalone host exit and machine-key removal.
mod project;
use super::*;
use crate::client::lease::Deadline;
use se_core::ops::{AgentStop, AnyOutput, project_remove::*, remove_commit, stop_plan::StopPlan};
use se_store::{Admission, EventBody, IntegrationState, Snapshot};
use se_types::{Named, ProjectId, Result};
use sha2::{Digest, Sha256};

impl LaunchCoordinator {
    async fn abandon_removal_notifications(
        &self,
        key: &se_types::IdempotencyKey,
        admission: Admission,
        deadline: &Deadline,
    ) -> Result<usize> {
        let effects = self
            .store
            .read(admission.clone(), deadline, remove_commit::pending_effects)
            .await?;
        let mut abandoned = 0;
        for effect in effects
            .into_iter()
            .filter(remove_commit::is_mail_notification)
        {
            let key = key.clone();
            self.store
                .commit(admission.clone(), deadline, None, move |kernel, cx| {
                    remove_commit::abandon_notification(kernel, &key, effect, cx)
                })
                .await?;
            abandoned += 1;
        }
        // The tombstone writer independently refuses any new live authority or
        // non-notification debt. Abandonment never alters the unread messages,
        // even if a concurrent launch makes registration removal refuse.
        Ok(abandoned)
    }
    pub async fn remove(
        self: &Arc<Self>,
        plan: RemovePlan,
        admission: Admission,
        deadline: &Deadline,
    ) -> Result<RemoveResult> {
        let key = format!(
            "{:?}/{:?}/{}",
            admission.scope, admission.actor, plan.input.idempotency_key
        );
        let intent = Sha256::digest(
            serde_json::to_vec(&serde_json::json!({
                "operation": "project.remove",
                "input": plan.input,
                "scope": format!("{:?}", admission.scope),
            }))
            .map_err(|e| error("removal request intent", e))?,
        )
        .into();
        let coordinator = Arc::downgrade(self);
        match self
            .supervise_control(key, intent, deadline, move |deadline| {
                let coordinator = coordinator.clone();
                let plan = plan.clone();
                let admission = admission.clone();
                async move {
                    coordinator
                        .upgrade()
                        .ok_or_else(|| error("removal retry", "the original host has retired"))?
                        .remove_selected(plan, admission, &deadline)
                        .await
                        .map(AnyOutput::from)
                }
            })
            .await?
        {
            AnyOutput::ProjectRemove(value) => Ok(value.value),
            _ => Err(se_core::scope::unreadable(
                "removal receipt",
                "the retained request belongs to another operation",
            )),
        }
    }
    async fn remove_selected(
        self: &Arc<Self>,
        plan: RemovePlan,
        admission: Admission,
        deadline: &Deadline,
    ) -> Result<RemoveResult> {
        let mut projects = Vec::with_capacity(plan.projects.len());
        for project in plan.projects {
            let mut admitted = admission.clone();
            admitted.scope = se_store::Scope::Project(project.id.clone());
            let mut row = empty(project.clone());
            if let Err(error) = self
                .remove_project(project, &plan.input, admitted, &mut row, deadline)
                .await
            {
                row.remaining
                    .push(obligation("project registration", &error.to_string(), None));
            }
            projects.push(row);
        }
        let mut partial = projects.iter().any(|p| p.outcome == "partial") || plan.input.all;
        let scope = if plan.input.all { "all" } else { "project" };
        let runtime_note = if plan.input.all {
            "The outside CLI must stop and witness the standalone host, then remove its machine credential; embedded SE Code stays running."
        } else {
            "The runtime remains available to initialized projects."
        };
        let owner = self.owner.clone();
        let at = deadline.at();
        let (process, runtime_witness) = match self
            .store
            .pool
            .run_owned(deadline, move || super::launch_util::view(&owner, at))
            .await
        {
            Ok(process) => (Some(process), unobserved("not-applicable", runtime_note)),
            Err(error) => {
                partial = true;
                (
                    None,
                    unobserved(
                        "unknown",
                        &format!(
                            "Project results above remain committed; the final runtime observation failed: {error}"
                        ),
                    ),
                )
            }
        };
        Ok(RemoveResult {
            idempotency_key:plan.input.idempotency_key,scope:scope.into(),
            outcome:if partial{"partial"}else if projects.is_empty(){"absent"}else{"removed"}.into(),projects,
            runtime:RemovedRuntime{action:"left-running".into(),process,witness:runtime_witness},
            machine_credential: RemovedMachineCredential {
                state: "kept".into(),
                witness: unobserved(
                    "not-applicable",
                    "The outside CLI retires the machine credential only after standalone exit is witnessed.",
                ),
            },
            next: RemovalNext {
                text: "Come back later with se init, or remove the installed executable with se uninstall.".into(),
                command: "se init".into(),
                argv: vec!["se".into(), "init".into()],
            },
        })
    }
}
fn empty(project: Named<ProjectId>) -> ProjectRemoval {
    ProjectRemoval {
        project: RemovedProject {
            id: project.id,
            name: project.name,
            root: "unreadable".into(),
        },
        outcome: "partial".into(),
        removed_at: None,
        event_id: None,
        agents_stopped: Vec::new(),
        processes_stopped: Vec::new(),
        processes_may_remain: Vec::new(),
        credentials_revoked: Vec::new(),
        integrations: Vec::new(),
        removed: Vec::new(),
        kept: Vec::new(),
        remaining: Vec::new(),
    }
}
fn unobserved(state: &str, detail: &str) -> RemovalWitness {
    RemovalWitness {
        state: state.into(),
        method: None,
        observed_at: None,
        detail: Some(detail.into()),
    }
}
fn obligation(
    what: &str,
    reason: &str,
    command: Option<se_core::ops::AgentCommand>,
) -> RemovalObligation {
    let (command, argv) = match command {
        Some(value) => (Some(value.command), Some(value.argv)),
        None => (None, None),
    };
    RemovalObligation {
        what: what.into(),
        reason: reason.into(),
        command,
        argv,
    }
}

fn process_state(state: se_store::ProcessState) -> &'static str {
    use se_store::ProcessState::*;
    match state {
        Reserved => "reserved",
        Starting => "starting",
        Running => "running",
        LeaderExited => "leader-exited",
        StopRequested => "stop-requested",
        StopUnproved => "stop-unproved",
        Exited => "exited",
        Lost => "lost",
        Historical => "historical",
    }
}
