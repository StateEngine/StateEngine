//! Owned adapter work. No closure, transaction, handle or authority from JSON.
use crate::{
    commit::{MessageSendThen, WorkingStateSetThen},
    ops::{ProjectInit, ProjectStatus, RuntimeDown, RuntimeUp, Uninstall},
};
pub enum Then {
    MessageSend(MessageSendThen),
    WorkingStateSet(WorkingStateSetThen),
}
pub enum CustodyPlan {
    Initialize(ProjectInit),
    /// A read-only native observation, followed by core status construction.
    ObserveStatus(ProjectStatus),
    RuntimeUp(RuntimeUp),
    RuntimeDown(RuntimeDown),
    Uninstall(Uninstall),
}
