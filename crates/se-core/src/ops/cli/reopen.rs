//! Resume context stays read-only; owner recovery names the existing launch path.
use super::*;

pub(super) fn refuse<R: se_store::Snapshot>(
    cx: &mut crate::commit::Cx<'_, R>,
    selector: &str,
) -> Result<()> {
    if !matches!(cx.admission.actor, se_store::Actor::Human(_)) {
        return Err(SeError::new(Detail::OwnerRequired(
            details::OwnerRequired {
                op: "reopen a saved agent".into(),
            },
        )));
    }
    let se_store::Actor::Agent(agent) = crate::scope::selected_actor(cx, selector)? else {
        return Err(SeError::invalid("resume agent", "a saved project agent"));
    };
    let project = crate::scope::project(cx.admission)?;
    let command = AgentCommand::launch(&agent, None, Some(&project), false);
    let mut error = SeError::new(Detail::UsageInvalidValue(details::UsageInvalidValue {
        argument: "se resume AGENT".into(),
        got: "provider conversation reopen".into(),
        expected: "a context read; use launch to reopen the saved conversation".into(),
    }));
    error.body = error.body.with_remedy(se_types::Remedy {
        text: "Reopen this agent's saved conversation with the command below.".into(),
        command: Some(se_types::Cmd::Se {
            argv: se_types::Argv::from_op(&command)?,
        }),
    });
    Err(error)
}
