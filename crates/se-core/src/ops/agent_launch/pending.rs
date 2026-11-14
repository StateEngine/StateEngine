//! A retained request can still be starting without an activated process receipt.
use super::{AgentLaunch, LaunchPlan, LaunchResult, TakeoverReport};
use crate::ops::AgentCommand;
use schemars::JsonSchema;
use se_config::config_policy::Provider;
use se_types::{AgentId, IdempotencyKey, LifecycleId, Named, ProjectId, SessionId};
use serde::{Deserialize, Serialize};

/// Running keeps its existing wire fields. Pending never invents the process,
/// conversation or committed event required by the activated receipt.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum LaunchReply {
    Running(Box<LaunchResult>),
    Pending(Box<LaunchPending>),
}
impl From<LaunchResult> for LaunchReply {
    fn from(value: LaunchResult) -> Self {
        Self::Running(Box::new(value))
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum LaunchPendingState {
    Starting,
    SetupNeeded,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LaunchPending {
    pub state: LaunchPendingState,
    pub idempotency_key: IdempotencyKey,
    pub lifecycle_id: LifecycleId,
    pub session_id: SessionId,
    pub project: Named<ProjectId>,
    pub agent: Named<AgentId>,
    pub provider: Provider,
    /// Repeat the same agent.launch operation with these original arguments.
    /// This does not require an owner-only status operation through MCP.
    pub retry: AgentLaunch,
    /// None when the original home or task cannot be rendered as one CLI line.
    pub retry_command: Option<AgentCommand>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub takeover: Option<TakeoverReport>,
}
impl LaunchPending {
    pub fn new(
        plan: &LaunchPlan,
        state: LaunchPendingState,
        home: &std::path::Path,
        takeover: Option<TakeoverReport>,
    ) -> Self {
        let mut retry = plan.input.clone();
        // CLI selectors and the MCP target ID have the same normalized intent.
        retry.target_agent_id = Some(plan.agent.id.clone());
        retry.owner_agent = None;
        retry.owner_provider = None;
        let retry_command = retry_command(&retry, plan, home);
        Self {
            state,
            idempotency_key: retry.idempotency_key.clone(),
            lifecycle_id: plan.lifecycle.clone(),
            session_id: plan.session.clone(),
            project: plan.project.clone(),
            agent: plan.agent.clone(),
            provider: Provider::Claude,
            retry,
            retry_command,
            takeover,
        }
    }
}

fn retry_command(
    retry: &AgentLaunch,
    plan: &LaunchPlan,
    home: &std::path::Path,
) -> Option<AgentCommand> {
    let mut argv =
        AgentCommand::launch_in_home(&plan.agent.id, home, &plan.project.id, retry.fresh)?
            .with_detach(retry.detach)
            .argv;
    argv.extend(["--key".into(), retry.idempotency_key.to_string()]);
    for (flag, value) in [("--model", &retry.model), ("--task", &retry.task)] {
        if let Some(value) = value {
            argv.extend([flag.into(), value.clone()]);
        }
    }
    if retry.override_live {
        argv.push("--force".into());
    }
    AgentCommand::from_argv(argv)
}
