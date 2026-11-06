//! Owned adapter work. No closure, transaction, handle or authority from JSON.
use crate::{
    commit::{MessageSendThen, WorkingStateSetThen},
    ops::{ProjectInit, ProjectStatus, RuntimeDown, RuntimeUp, Uninstall},
};
pub enum Then {
    AgentConfig(crate::ops::agent_config::AgentConfigThen),
    AgentCreate(crate::ops::agent::AgentCreateThen),
    Decision(crate::ops::decision::DecisionThen),
    Capture(crate::ops::hook::CaptureThen),
    MessageSend(MessageSendThen),
    MessageMark(crate::ops::message_mark::MarkThen),
    WorkingStateSet(WorkingStateSetThen),
}
pub enum CustodyPlan {
    AtlasRead(Box<crate::ops::atlas::AtlasRead>),
    AtlasAugment(crate::ops::AtlasAugment),
    Launch(Box<crate::ops::agent_launch::LaunchPlan>),
    Stop(Box<crate::ops::stop_plan::StopPlan>),
    Remove(Box<crate::ops::project_remove::RemovePlan>),
    ClaudeHook(crate::ops::hook::HookClaude),
    Initialize(ProjectInit),
    ImportNode(crate::ops::ImportNode),
    /// A read-only native observation, followed by core status construction.
    ObserveStatus(ProjectStatus),
    RuntimeUp(RuntimeUp),
    RuntimeDown(RuntimeDown),
    Uninstall(Uninstall),
}
