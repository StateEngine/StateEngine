//! Find or atomically create the initial saved identity, then read it back.
use super::*;
pub(super) fn initial_agent(
    input: &ProjectInit,
    store: &mut SqliteDirect,
    lease: &DirectLease,
    admission: &Admission,
    configuration: &se_config::config_policy::ConfigFile,
) -> Result<(AgentRow, bool)> {
    let mut snap = super::super::select::open_snapshot(store, admission)?;
    let found = project::find_saved_agent(&mut snap, &input.agent);
    let found = execute::finish_read(found, snap.close().map_err(|e| store_error(&e)))?;
    let (agent, created) = match found {
        Some(agent) => (agent, false),
        None => create_initial_agent(input, store, lease, admission, configuration)?,
    };
    let mut snap = super::super::select::open_snapshot(store, admission)?;
    let row = project::read_saved_agent(
        &mut Cx {
            read: &mut snap,
            admission,
        },
        &agent,
    );
    let row = execute::finish_read(row, snap.close().map_err(|e| store_error(&e)))?;
    project::verify_saved_agent(&row, input)?;
    Ok((row, created))
}
fn create_initial_agent(
    input: &ProjectInit,
    store: &mut SqliteDirect,
    lease: &DirectLease,
    admission: &Admission,
    configuration: &se_config::config_policy::ConfigFile,
) -> Result<(AgentId, bool)> {
    let kernel = Kernel::new(execute::facts()?)?.with_configuration(configuration.clone())?;
    let op = project::initial_agent_op(input)?;
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
