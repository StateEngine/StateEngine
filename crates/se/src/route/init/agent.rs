//! Find or atomically create the initial saved identity, then read it back.
use super::*;
pub(super) fn initial_agent(
    input: &ProjectInit,
    store: &mut SqliteDirect,
    lease: &DirectLease,
    admission: &Admission,
    configuration: &se_config::config_policy::ConfigFile,
) -> Result<(AgentRow, bool)> {
    let found = saved_agent(store, admission, &input.agent)?;
    let (agent, created) = match found {
        Some(agent) => (agent, false),
        None => create_initial_agent(input, store, lease, admission, configuration)?,
    };
    let row = saved_agent_row(store, admission, &agent)?;
    verify_saved_row(&row, input)?;
    Ok((row, created))
}
fn saved_agent(
    store: &mut SqliteDirect,
    admission: &Admission,
    agent_name: &str,
) -> Result<Option<AgentId>> {
    let mut snap = super::super::select::open_snapshot(store, admission)?;
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
                && name == agent_name
                && found.replace(agent.clone()).is_some()
            {
                return Err(scope::unreadable(
                    "initial agent",
                    "saved name is ambiguous",
                ));
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
    Ok(found)
}
fn create_initial_agent(
    input: &ProjectInit,
    store: &mut SqliteDirect,
    lease: &DirectLease,
    admission: &Admission,
    configuration: &se_config::config_policy::ConfigFile,
) -> Result<(AgentId, bool)> {
    let kernel = Kernel::new(execute::facts()?)?.with_configuration(configuration.clone())?;
    let op = AnyOp::AgentCreate(AgentCreate {
        provider_settings: Default::default(),
        harness: input.harness.clone(),
        name: input.agent.clone(),
        provider: input.provider,
        model: input.model.clone(),
        profile: None,
        idempotency_key: phase_key(&input.idempotency_key, "agent")?,
    });
    match crate::route::direct::execute(
        store,
        lease,
        admission,
        &se_core::admission::HumanTerminal::Refused {
            reason: "setup creates a safe saved identity without claiming human presence".into(),
        },
        &kernel,
        op,
        &CliSelections::default(),
    )? {
        crate::route::direct::Outcome::Complete(AnyOutput::AgentCreate(value))
        | crate::route::direct::Outcome::Committed {
            output: AnyOutput::AgentCreate(value),
            ..
        } => {
            let created = value.value.outcome == AgentOutcome::Created;
            Ok((value.value.agent.id, created))
        }
        _ => Err(scope::unreadable(
            "initial agent",
            "atomic identity/profile creation did not return its receipt",
        )),
    }
}
fn saved_agent_row(
    store: &mut SqliteDirect,
    admission: &Admission,
    agent: &AgentId,
) -> Result<AgentRow> {
    let mut snap = super::super::select::open_snapshot(store, admission)?;
    let output = agent_status::show(
        AgentShow {
            target_agent_id: Some(agent.clone()),
        },
        &mut Cx {
            read: &mut snap,
            admission,
        },
    );
    snap.close().map_err(|e| store_error(&e))?;
    scope::require_present(
        output?.agent,
        "initial saved agent",
        "Read the original saved agent in this data home, then retry se init with its original --key; preserve existing agent identities.",
    )
}
fn verify_saved_row(row: &AgentRow, input: &ProjectInit) -> Result<()> {
    if input
        .provider
        .is_some_and(|provider| row.provider != provider)
    {
        return Err(se_types::SeError::invalid(
            "initial provider",
            "the existing agent keeps its saved provider; select a new --agent name to choose a different harness",
        ));
    }
    if input
        .harness
        .as_ref()
        .is_some_and(|selected| row.harness.as_ref() != Some(selected))
    {
        return Err(se_types::SeError::invalid(
            "initial harness",
            "the existing agent keeps its saved harness; create another agent with --harness to select a different one",
        ));
    }
    Ok(())
}
