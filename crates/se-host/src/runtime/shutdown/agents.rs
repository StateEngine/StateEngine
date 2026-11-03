//! Independent per-lifecycle exit facts; aggregate custody success is not one.
use super::*;
use crate::client::closure::AgentClosure;
use se_core::{scope, store_error::store_error};
use se_store::{Actor, Admission, EventBody, ReadScope, ReadStore, Scope, Snapshot, Visibility};

pub(super) async fn observe(
    runtime: &HostedRuntime,
    targets: &[AgentClosure],
    deadline: &Deadline,
) -> Vec<AgentClosure> {
    let reader = runtime.execution.reader.clone();
    let owner = runtime.owner.clone();
    let generation = runtime.generation().get();
    let originals = targets.to_vec();
    let mut observed = originals.clone();
    let bound = deadline.clone();
    match runtime
        .execution
        .blocking
        .run_owned(deadline, move || {
            for target in &mut observed {
                let result = (|| {
                    bound.remaining()?;
                    let mut read = reader
                        .snapshot(ReadScope {
                            admission: Admission {
                                scope: Scope::Project(target.project.clone()),
                                actor: Actor::Human(owner.clone()),
                                session: None,
                                generation,
                            },
                            visibility: Visibility::Owner,
                        })
                        .map_err(|e| store_error(&e))?;
                    let result = exit(&mut read, target);
                    super::super::executor::close_read(result, read.close())
                })();
                match result {
                    Ok(witness) => {
                        target.witness = Some(witness);
                        target.reason = None;
                    }
                    Err(error) => target.reason = Some(error.to_string()),
                }
            }
            Ok(observed)
        })
        .await
    {
        Ok(observed) => observed,
        Err(error) => originals
            .into_iter()
            .map(|mut target| {
                target.reason = Some(error.to_string());
                target
            })
            .collect(),
    }
}
fn exit<R: Snapshot>(read: &mut R, target: &AgentClosure) -> Result<se_proc::StopWitness> {
    let record = scope::require_present(
        read.process(target.lifecycle.clone())
            .map_err(|e| store_error(&e))?,
        "shutdown per-agent exit",
        "Preserve this lifecycle's original native checkpoint and restore its protected readback.",
    )?;
    let EventBody::ProcessTransition {
        identity,
        to: se_store::ProcessState::Exited,
        ..
    } = &record.current.body
    else {
        return Err(scope::unreadable(
            "shutdown per-agent exit",
            "this exact lifecycle has no terminal native exit checkpoint",
        ));
    };
    if identity.record != target.lifecycle
        || identity.principal != Actor::Agent(target.agent.clone())
        || identity.session.as_ref() != Some(&target.session)
    {
        return Err(scope::unreadable(
            "shutdown per-agent exit",
            "the terminal checkpoint belongs to a different lifecycle or principal",
        ));
    }
    let checkpoint =
        se_proc::decode_checkpoint(identity.custody.format_version, &identity.custody.record)
            .map_err(|e| scope::unreadable("shutdown native exit checkpoint", &e.to_string()))?;
    if checkpoint.lifecycle != target.lifecycle
        || checkpoint.session.as_ref() != Some(&target.session)
        || !matches!(&checkpoint.principal, se_proc::CheckpointPrincipal::Agent(agent) if agent == &target.agent)
    {
        return Err(scope::unreadable(
            "shutdown native exit checkpoint",
            "the checkpoint differs from the original agent/session/lifecycle binding",
        ));
    }
    let se_proc::CheckpointKind::Exit { witness, .. } = checkpoint.checkpoint else {
        return Err(scope::unreadable(
            "shutdown native exit checkpoint",
            "an exited projection has no exit witness",
        ));
    };
    if witness.lifecycle != target.lifecycle
        || witness.scope_exit.scope != witness.scope
        || witness.scope_exit.remaining.population != se_proc::Population::Empty
        || witness.scope_exit.exit_basis.is_none()
    {
        return Err(scope::unreadable(
            "shutdown native exit checkpoint",
            "the original lifecycle's exact scope exit remains unproved",
        ));
    }
    Ok(witness)
}
