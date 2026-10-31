//! Find or atomically create the initial saved identity, then read it back.
use super::*;
pub(super) fn initial_agent(
    cx: &Bootstrap,
    input: &ProjectInit,
    store: &mut SqliteDirect,
    lease: &DirectLease,
    admission: &Admission,
) -> Result<(AgentRow, bool)> {
    let mut snap = store
        .snapshot(read_scope(admission))
        .map_err(|e| store_error(&e))?;
    let mut after = None;
    let mut found = None;
    let mut complete = false;
    for _ in 0..64 {
        let page = snap
            .principals(select::budget(after)?)
            .map_err(|e| store_error(&e))?;
        for record in page.items() {
            if let EventBody::PrincipalRegistered {
                principal: Actor::Agent(agent),
                name,
                ..
            }
            | EventBody::PrincipalRenamed {
                principal: Actor::Agent(agent),
                name,
                ..
            } = &record.current.body
            {
                if name == &input.agent {
                    if found.is_some() {
                        return Err(scope::unreadable(
                            "initial agent",
                            "saved name is ambiguous",
                        ));
                    }
                    found = Some(agent.clone());
                }
            }
        }
        match page.next() {
            Some(next) => after = Some(next.clone()),
            None if page.window().complete() => {
                complete = true;
                break;
            }
            None => {
                return Err(scope::unreadable(
                    "initial agent",
                    "principal inventory is incomplete",
                ));
            }
        }
        if after.is_some() && page.items().is_empty() {
            return Err(scope::unreadable(
                "initial agent",
                "nonprogressing principal inventory",
            ));
        }
    }
    snap.close().map_err(|e| store_error(&e))?;
    if !complete {
        return Err(scope::unreadable(
            "initial agent",
            "principal inventory exceeded its finite bound",
        ));
    }
    let created = found.is_none();
    let agent: AgentId = match found {
        Some(agent) => agent,
        None => {
            let kernel =
                Kernel::new(execute::facts()?)?.with_configuration(cx.config.value.clone())?;
            let op = AnyOp::AgentCreate(AgentCreate {
                name: input.agent.clone(),
                provider: input.provider,
                model: input.model.clone(),
                idempotency_key: phase_key(&input.idempotency_key, "agent")?,
            });
            match crate::route::direct::execute(
                store,
                lease,
                admission,
                &se_core::admission::HumanTerminal::Refused {
                    reason: "setup creates a safe saved identity without claiming human presence"
                        .into(),
                },
                &kernel,
                op,
                &CliSelections::default(),
            )? {
                crate::route::direct::Outcome::Complete(AnyOutput::AgentCreate(value)) => {
                    value.value.agent.id
                }
                _ => {
                    return Err(scope::unreadable(
                        "initial agent",
                        "atomic identity/profile creation did not return its receipt",
                    ));
                }
            }
        }
    };
    let mut snap = store
        .snapshot(read_scope(admission))
        .map_err(|e| store_error(&e))?;
    let output = agent_status::show(
        AgentShow {
            target_agent_id: Some(agent),
        },
        &mut Cx {
            read: &mut snap,
            admission,
        },
    );
    snap.close().map_err(|e| store_error(&e))?;
    Ok((
        scope::require_present(output?.agent, "initial saved agent")?,
        created,
    ))
}
