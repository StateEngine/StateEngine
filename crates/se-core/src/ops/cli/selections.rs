//! Trusted CLI selections are reapplied inside the admitted host snapshot;
//! model JSON never supplies these routing fields.
use super::*;

/// Authenticated CLI routing metadata, separate from model-facing operation DTOs.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CliSelections {
    /// Resolved from CLI project policy before forwarding; never an authority.
    /// The host must select/check this scope before opening an admitted snapshot.
    pub project: Option<se_types::ProjectId>,
    pub agent: Option<String>,
    pub mail_to: Option<String>,
    pub mail_list: bool,
    pub status_all: bool,
    pub control_all: bool,
    pub stop_release: bool,
    pub launch_provider: Option<crate::config_policy::Provider>,
}
impl CliSelections {
    pub fn validate(&self) -> Result<()> {
        for (name, selector) in [("agent", &self.agent), ("to", &self.mail_to)] {
            if let Some(selector) = selector {
                bounded(name, selector, 512, false)?;
            }
        }
        if self.status_all && self.project.is_some() {
            return Err(SeError::invalid(
                "--all",
                "no simultaneous project selector",
            ));
        }
        Ok(())
    }
    /// Called only by the authenticated CLI route inside its admitted finite read.
    /// The same metadata crosses IPC separately; MCP arguments never carry it.
    pub fn apply<R: se_store::Snapshot>(
        &self,
        op: &mut AnyOp,
        cx: &mut crate::commit::Cx<'_, R>,
    ) -> Result<()> {
        self.validate()?;
        if let Some(project) = &self.project
            && cx.admission.scope != se_store::Scope::Project(project.clone())
        {
            return Err(SeError::invalid(
                "CLI project routing",
                "the resolved project must match the verified admission scope before reading",
            ));
        }
        if self.status_all {
            match op {
                AnyOp::ProjectStatus(input) => input.all = true,
                _ => {
                    return Err(unknown_flag(
                        "--all",
                        op.meta().name,
                        "only status accepts all-project routing",
                    ));
                }
            }
        }
        if self.control_all {
            match op {
                AnyOp::AgentStop(input) => input.all = true,
                AnyOp::ProjectRemove(input) if input.all => (),
                _ => {
                    return Err(unknown_flag(
                        "--all",
                        op.meta().name,
                        "only stop or remove accepts control-all selection",
                    ));
                }
            }
        }
        if self.stop_release {
            match op {
                AnyOp::AgentStop(input) => input.release = true,
                _ => {
                    return Err(unknown_flag(
                        "--release",
                        op.meta().name,
                        "only a single-agent stop can release ownership",
                    ));
                }
            }
        }
        if let Some(provider) = self.launch_provider {
            match op {
                AnyOp::AgentLaunch(input) => input.owner_provider = Some(provider),
                _ => {
                    return Err(unknown_flag(
                        "--provider",
                        op.meta().name,
                        "this control selection is only a launch override",
                    ));
                }
            }
        }
        if let Some(selector) = &self.agent {
            match op {
                // Keep control selection in its own path: the core planner's
                // control_target read applies the current direct-creator grant.
                AnyOp::AgentLaunch(input) => input.owner_agent = Some(selector.clone()),
                AnyOp::AgentStop(input) => input.owner_agent = Some(selector.clone()),
                AnyOp::WorkingStateGet(_)
                | AnyOp::WorkingStateSet(_)
                | AnyOp::AgentShow(_)
                | AnyOp::HistoryList(_) => {
                    let actor = crate::scope::actor_selector(cx.read, selector)?;
                    let se_store::Actor::Agent(agent) = actor else {
                        return Err(SeError::invalid("agent", "a project agent, not the owner"));
                    };
                    crate::scope::working_agent(cx.admission, Some(&agent), op.meta().name)?;
                    match op {
                        AnyOp::AgentShow(input) => input.target_agent_id = Some(agent),
                        AnyOp::HistoryList(input) => input.owner_agent = Some(agent),
                        AnyOp::WorkingStateGet(input) => input.owner_agent = Some(agent),
                        AnyOp::WorkingStateSet(input) => input.owner_agent = Some(agent),
                        _ => (),
                    }
                }
                _ => {
                    return Err(unknown_flag(
                        "--agent",
                        op.meta().name,
                        "this operation has no agent selector",
                    ));
                }
            }
        }
        if self.mail_list || self.mail_to.is_some() {
            match op {
                AnyOp::MessageList(input) => {
                    input.cli_list = self.mail_list;
                    input.owner_to = self.mail_to.clone();
                }
                _ => {
                    return Err(unknown_flag(
                        "--to",
                        op.meta().name,
                        "this operation has no mail filter",
                    ));
                }
            }
        }
        Ok(())
    }
}
