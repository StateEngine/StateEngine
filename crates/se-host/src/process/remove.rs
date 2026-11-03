//! Stop and clean each selected project independently, then commit its
//! tombstone. The outside CLI owns standalone host exit and machine-key removal.
use super::*;
use crate::client::lease::Deadline;
use se_core::ops::{AgentStop, AnyOutput, project_remove::*, remove_commit, stop_plan::StopPlan};
use se_store::{Admission, EventBody, IntegrationState, Snapshot};
use se_types::{Named, ProjectId, Result};
use sha2::{Digest, Sha256};

impl LaunchCoordinator {
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
        let intent=Sha256::digest(serde_json::to_vec(&serde_json::json!({"operation":"project.remove","input":plan.input,"scope":format!("{:?}",admission.scope)})).map_err(|e|error("removal request intent",e))?).into();
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
            machine_credential:RemovedMachineCredential{state:"kept".into(),witness:unobserved("not-applicable","The outside CLI retires the machine credential only after standalone exit is witnessed.")},
            next:RemovalNext{text:"Come back later with se init, or remove the installed executable with se uninstall.".into(),command:"se init".into(),argv:vec!["se".into(),"init".into()]},
        })
    }
    async fn remove_project(
        self: &Arc<Self>,
        project: Named<ProjectId>,
        input: &ProjectRemove,
        admission: Admission,
        row: &mut ProjectRemoval,
        deadline: &Deadline,
    ) -> Result<()> {
        let selected = project.clone();
        let inventory = self
            .store
            .read(admission.clone(), deadline, move |cx| {
                remove_commit::inventory(selected, cx)
            })
            .await?;
        row.project.root = inventory.root.to_local()?.display().to_string();
        row.kept = vec![
            KeptItem {
                what: "history".into(),
                path: None,
                note: "Messages, decisions, turns and receipts remain available.".into(),
            },
            KeptItem {
                what: "repo-files".into(),
                path: Some(row.project.root.clone()),
                note: "Repository work is preserved.".into(),
            },
            KeptItem {
                what: "git-history".into(),
                path: Some(row.project.root.clone()),
                note: "Git history is preserved.".into(),
            },
            KeptItem {
                what: "provider-transcripts".into(),
                path: None,
                note: "Provider transcripts remain in their provider-owned location.".into(),
            },
            KeptItem {
                what: "backups".into(),
                path: None,
                note: "Existing backups are preserved.".into(),
            },
        ];
        let stop_key = se_core::ops::process_commit::phase_key(
            &input.idempotency_key,
            &format!("{}/stop", project.id),
        )?;
        let mut lifecycle_by_session = std::collections::BTreeMap::new();
        let mut prior_states = std::collections::BTreeMap::new();
        for agent in &inventory.agents {
            if let se_types::Read::Present { value } = &agent.control.latest_process {
                let state = match &value.current.body {
                    EventBody::ProcessRegistered { initial, .. } => *initial,
                    EventBody::ProcessTransition { to, .. } => *to,
                    _ => {
                        return Err(error(
                            "removal inventory",
                            "latest process has no recorded state",
                        ));
                    }
                };
                prior_states.insert(
                    agent.target.agent.id.clone(),
                    process_state(state).to_owned(),
                );
            }
            for head in agent
                .control
                .processes
                .iter()
                .chain(match &agent.control.latest_process {
                    se_types::Read::Present { value } => Some(value),
                    _ => None,
                })
            {
                let identity = match &head.current.body {
                    EventBody::ProcessRegistered { identity, .. }
                    | EventBody::ProcessTransition { identity, .. } => identity,
                    _ => continue,
                };
                if let Some(session) = &identity.session {
                    lifecycle_by_session.insert(session.clone(), identity.record.clone());
                }
            }
        }
        let stopped = self
            .stop_selected(
                StopPlan {
                    input: AgentStop {
                        target_agent_id: None,
                        idempotency_key: stop_key,
                        owner_agent: None,
                        all: true,
                        release: false,
                    },
                    projects: vec![project.clone()],
                    targets: inventory.agents,
                },
                admission.clone(),
                deadline,
            )
            .await?;
        let mut witnesses = Vec::new();
        let stops = stopped.stops.ok_or_else(|| {
            error(
                "removal stop receipt",
                "all-target stop omitted its per-target results",
            )
        })?;
        for stop in stops {
            match stop.result.as_str() {
                "stopped" => {
                    if let Some(event) = &stop.event_id {
                        witnesses.push(event.clone());
                    }
                    if let (Some(session), Some(process)) =
                        (&stop.target.session_id, &stop.target.process)
                    {
                        let lifecycle =
                            lifecycle_by_session.get(session).cloned().ok_or_else(|| {
                                error(
                                    "removal process receipt",
                                    "the stopped session has no exact inventory lifecycle",
                                )
                            })?;
                        row.processes_stopped.push(RemovedProcess {
                            lifecycle_id: lifecycle,
                            process: process.clone(),
                            witness: RemovalWitness {
                                state: stop.witness.state.clone(),
                                method: stop.witness.method.clone(),
                                observed_at: stop.witness.observed_at.clone(),
                                detail: stop.witness.detail.clone(),
                            },
                        });
                    }
                    if let Some(session) = &stop.target.session_id {
                        row.credentials_revoked.extend(
                            self.revoked_credentials(session.clone(), admission.clone(), deadline)
                                .await?,
                        );
                    }
                    row.agents_stopped.push(RemovedAgent {
                        agent: stop.target.agent.clone(),
                        prior_state: prior_states
                            .get(&stop.target.agent.id)
                            .cloned()
                            .ok_or_else(|| {
                                error(
                                    "removal receipt",
                                    "stopped agent has no recorded prior process state",
                                )
                            })?,
                        witness: RemovalWitness {
                            state: stop.witness.state,
                            method: stop.witness.method,
                            observed_at: stop.witness.observed_at,
                            detail: stop.witness.detail,
                        },
                        process: stop.target.process,
                    });
                }
                "already-stopped" => (),
                "ownership-released" => row.processes_may_remain.push(stop),
                _ => row.remaining.push(obligation(
                    "agent process",
                    stop.population_reason
                        .as_deref()
                        .unwrap_or("Native exit or capture cleanup remains unproved."),
                    Some(vec![
                        "se".into(),
                        "stop".into(),
                        "--agent".into(),
                        stop.target.agent.id.to_string(),
                    ]),
                )),
            }
        }
        if let Some(reason) = stopped.population_reason {
            row.remaining
                .push(obligation("agent inventory", &reason, None));
        }
        for integration in inventory.integrations {
            let (path, entry, state) = match &integration.current.body {
                EventBody::IntegrationRecorded {
                    path, key, state, ..
                } => (path.to_local()?.display().to_string(), key.clone(), *state),
                _ => {
                    return Err(se_core::scope::unreadable(
                        "removal integration",
                        "wrong projection",
                    ));
                }
            };
            if state == IntegrationState::Removed {
                row.integrations.push(RemovedIntegration {
                    path,
                    entry,
                    action: "absent".into(),
                    witness: unobserved(
                        "not-applicable",
                        "This integration already has a removed record.",
                    ),
                });
                continue;
            }
            if input.keep_integrations {
                if state == IntegrationState::Installed {
                    let key = input.idempotency_key.clone();
                    let head = integration.clone();
                    let receipt = self
                        .store
                        .commit(admission.clone(), deadline, None, move |kernel, cx| {
                            remove_commit::keep_integration(kernel, &key, head, cx)
                        })
                        .await?;
                    witnesses.push(receipt.primary_event);
                }
                row.integrations.push(RemovedIntegration {
                    path,
                    entry,
                    action: "kept-by-flag".into(),
                    witness: unobserved(
                        "not-applicable",
                        "The owner explicitly requested preserving this integration.",
                    ),
                });
                continue;
            }
            let key = input.idempotency_key.clone();
            let head = integration.clone();
            let requested = self
                .store
                .commit(admission.clone(), deadline, None, move |kernel, cx| {
                    remove_commit::integration_request(kernel, &key, &head, cx)
                })
                .await?;
            let head = integration.clone();
            let observed = self
                .store
                .pool
                .run_owned(deadline, move || super::integration::reverse(&head))
                .await?;
            let effect = match &integration.current.body {
                EventBody::IntegrationRecorded {
                    integration: id, ..
                } => remove_commit::integration_effect(&input.idempotency_key, *id)?,
                _ => unreachable!(),
            };
            let effect_head = self
                .store
                .read(admission.clone(), deadline, move |cx| {
                    se_core::scope::require_present(
                        cx.read
                            .effect(effect)
                            .map_err(|e| se_core::store_error::store_error(&e))?,
                        "integration intention",
                        "Retain the original removal key.",
                    )
                })
                .await?;
            let key = input.idempotency_key.clone();
            let fact = observed.clone();
            let receipt = self
                .store
                .commit(admission.clone(), deadline, None, move |kernel, cx| {
                    remove_commit::settle_integration(
                        kernel,
                        &key,
                        remove_commit::IntegrationSettlement {
                            prior: integration,
                            request: requested.primary_event,
                            effect_revision: effect_head.revision,
                            state: fact.state,
                            observed_hash: fact.digest,
                            failure: fact.failure,
                        },
                        cx,
                    )
                })
                .await?;
            witnesses.push(receipt.primary_event);
            if let Some(failure) = &observed.failure {
                row.remaining
                    .push(obligation("owned integration", failure, None));
            }
            row.integrations.push(RemovedIntegration {
                path,
                entry,
                action: observed.action,
                witness: RemovalWitness {
                    state: if observed.failure.is_some() {
                        "unwitnessed"
                    } else {
                        "witnessed"
                    }
                    .into(),
                    method: Some("readback".into()),
                    observed_at: Some(observed.observed_at),
                    detail: observed.failure,
                },
            });
        }
        if !inventory.effects.is_empty() {
            row.remaining.push(obligation("pending effects","Pre-existing effect delivery or settlement remains outstanding; registration is preserved.",None));
        }
        if !row.remaining.is_empty() {
            return Ok(());
        }
        // A current snapshot and the store's live-authority checks prevent a
        // concurrent launch or new effect from being hidden by removal.
        let id = project.id.clone();
        let current = self
            .store
            .read(admission.clone(), deadline, move |cx| {
                se_core::scope::require_present(
                    cx.read
                        .project(id)
                        .map_err(|e| se_core::store_error::store_error(&e))?,
                    "removal registration",
                    "Keep the original removal key.",
                )
            })
            .await?;
        if witnesses.is_empty() {
            witnesses.push(current.current.header.event.clone());
        }
        // The writer independently checks that no live authority or effect
        // debt remains. The latest reference closes the same finite inventory;
        // a receipt need not repeat every historical stop reference.
        if witnesses.len() > 64 {
            witnesses = vec![
                witnesses
                    .pop()
                    .ok_or_else(|| error("removal witness", "empty inventory"))?,
            ];
        }
        let key = input.idempotency_key.clone();
        let id = project.id;
        let receipt = self
            .store
            .commit(admission.clone(), deadline, None, move |kernel, cx| {
                remove_commit::tombstone(kernel, &key, id, current.revision, witnesses, cx)
            })
            .await?;
        let event = receipt.primary_event.clone();
        let at = self
            .store
            .read(admission, deadline, move |cx| {
                let event = se_core::scope::require_present(
                    cx.read
                        .event(event)
                        .map_err(|e| se_core::store_error::store_error(&e))?,
                    "removal receipt",
                    se_core::scope::COMMITTED_READ_RECOVERY,
                )?;
                se_core::ops::receipt::timestamp(event.recorded_at_us)
            })
            .await;
        let at = match at {
            Ok(at) => at,
            Err(error) => {
                row.event_id = Some(receipt.primary_event);
                row.outcome = "partial".into();
                row.remaining.push(obligation("committed registration removal",&format!("The removal committed, but its receipt time is unavailable: {error}; retry the original key."),None));
                return Ok(());
            }
        };
        row.outcome = "removed".into();
        row.removed_at = Some(at);
        row.event_id = Some(receipt.primary_event);
        row.removed.push(RemovedItem {
            what: "registration".into(),
            path: None,
        });
        Ok(())
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
fn obligation(what: &str, reason: &str, argv: Option<Vec<String>>) -> RemovalObligation {
    RemovalObligation {
        what: what.into(),
        reason: reason.into(),
        command: argv.as_ref().map(|args| args.join(" ")),
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
