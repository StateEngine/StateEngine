//! Bounded protected readbacks for shutdown, separate from transport and lease facts.
use super::*;
use se_core::{scope, store_error::store_error};
use se_store::{Actor, Admission, EventBody, ReadScope, ReadStore, Scope, Snapshot, Visibility};

pub(super) struct Before {
    pub resumes: Vec<RuntimeStopResume>,
    pub targets: Vec<crate::client::closure::AgentClosure>,
    pub had_process_records: bool,
}

pub(super) async fn before(runtime: &HostedRuntime, deadline: &Deadline) -> Result<Before> {
    let reader = runtime.execution.reader.clone();
    let lease = runtime.lease.clone();
    let owner = runtime.owner.clone();
    let generation = runtime.generation().get();
    let bound = deadline.clone();
    runtime
        .execution
        .blocking
        .run_owned(deadline, move || {
            read_before(&reader, &lease, owner, generation, &bound)
        })
        .await
}

fn read_before(
    reader: &se_store::SqliteReader,
    lease: &HostLease,
    owner: se_types::HumanId,
    generation: u64,
    bound: &Deadline,
) -> Result<Before> {
    bound.remaining()?;
    let mut budget = super::super::start::owner_budget()?;
    budget.deadline = budget.deadline.min(bound.remaining()?);
    let inventory = reader
        .owner_guard(&lease.files, budget)
        .map_err(|e| store_error(&e))?;
    let mut resumes = Vec::new();
    let mut targets = Vec::new();
    for process in &inventory.processes {
        let (Actor::Agent(agent), Some(session)) =
            (&process.identity.principal, &process.identity.session)
        else {
            if process.identity.root_identity == se_store::RootIdentityState::NoChildCreated {
                continue;
            }
            return Err(scope::unreadable(
                "shutdown resume inventory",
                "owned native process has no recorded agent/session binding",
            ));
        };
        bound.remaining()?;
        let mut read = reader
            .snapshot(ReadScope {
                admission: Admission {
                    scope: Scope::Project(process.project.clone()),
                    actor: Actor::Human(owner.clone()),
                    session: None,
                    generation,
                },
                visibility: Visibility::Owner,
            })
            .map_err(|e| store_error(&e))?;
        let result = (|| {
            let saved = scope::require_present(
                read.session(session.clone()).map_err(|e| store_error(&e))?,
                "shutdown original conversation",
                "Preserve the original session and repair its protected metadata before retrying shutdown.",
            )?;
            let original = saved.original.as_deref().unwrap_or(&saved.current);
            let EventBody::SessionPrepared {
                session: actual,
                agent: actual_agent,
                native_ref,
                ..
            } = &original.body
            else {
                return Err(scope::unreadable(
                    "shutdown original conversation",
                    "original preparation metadata is unavailable",
                ));
            };
            if actual != session || actual_agent != agent {
                return Err(scope::unreadable(
                    "shutdown original conversation",
                    "the original session differs from native custody",
                ));
            }
            if !native_ref.is_empty() {
                let retained = RuntimeStopResume {
                    project: process.project.clone(),
                    agent: agent.clone(),
                    conversation: se_types::ProviderSessionId::new(native_ref.clone())?,
                };
                if !resumes.iter().any(|old: &RuntimeStopResume| {
                    old.project == retained.project
                        && old.agent == retained.agent
                        && old.conversation == retained.conversation
                }) {
                    resumes.push(retained);
                }
            }
            targets.push(crate::client::closure::AgentClosure {
                project: process.project.clone(),
                agent: agent.clone(),
                session: session.clone(),
                conversation: if native_ref.is_empty() {
                    None
                } else {
                    Some(se_types::ProviderSessionId::new(native_ref.clone())?)
                },
                lifecycle: process.identity.record.clone(),
                witness: None,
                reason: Some(
                    "No per-lifecycle exit checkpoint has been read after shutdown.".into(),
                ),
            });
            Ok(())
        })();
        super::super::executor::close_read(result, read.close())?;
    }
    Ok(Before {
        resumes,
        targets,
        had_process_records: inventory.has_process_records,
    })
}

pub(super) async fn remaining(runtime: &HostedRuntime, deadline: &Deadline) -> Result<bool> {
    let reader = runtime.execution.reader.clone();
    let lease = runtime.lease.clone();
    let bound = deadline.clone();
    runtime
        .execution
        .blocking
        .run_owned(deadline, move || {
            bound.remaining()?;
            let mut budget = super::super::start::owner_budget()?;
            budget.deadline = budget.deadline.min(bound.remaining()?);
            let inventory = reader
                .owner_guard(&lease.files, budget)
                .map_err(|e| store_error(&e))?;
            Ok(!inventory.processes.is_empty())
        })
        .await
}
