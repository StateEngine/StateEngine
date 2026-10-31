//! Owned adapter work. No closure, transaction, handle or authority from JSON.
use crate::{
    commit::{MessageSendThen, WorkingStateSetThen},
    ops::{ProjectInit, ProjectStatus, RuntimeDown, RuntimeUp, Uninstall},
};
pub enum Then {
    Capture(crate::ops::hook::CaptureThen),
    MessageSend(MessageSendThen),
    WorkingStateSet(WorkingStateSetThen),
}
pub enum CustodyPlan {
    ClaudeHook(crate::ops::hook::HookClaude),
    Initialize(ProjectInit),
    /// A read-only native observation, followed by core status construction.
    ObserveStatus(ProjectStatus),
    RuntimeUp(RuntimeUp),
    RuntimeDown(RuntimeDown),
    Uninstall(Uninstall),
}
