//! CLI console observation carried over an authenticated owner connection.
//! This is a mistake/drift guard, not authority against hostile same-user code.
//! The host independently rechecks the native peer's owner and managed ancestry.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerPresence {
    os_owner: String,
    stdin_console: bool,
    stdout_console: bool,
    session_present: bool,
    provider_marker_present: bool,
    outside_agent_tree: bool,
}
impl OwnerPresence {
    /// Supply only the current CLI's native `observe_owner_self` result, using
    /// its complete protected process inventory. No argv/environment assertion
    /// constructs a passing observation.
    pub fn from_observation(observed: &se_proc::OwnerObservation) -> Self {
        let os_owner = match observed.owner() {
            se_proc::NativeOwner::Unix {
                real_uid,
                effective_uid,
            } if real_uid == effective_uid => effective_uid.to_string(),
            se_proc::NativeOwner::Windows { sid } => sid.clone(),
            _ => String::new(),
        };
        Self {
            os_owner,
            stdin_console: observed.stdin_console(),
            stdout_console: observed.stdout_console(),
            session_present: observed.session_present(),
            provider_marker_present: observed.provider_marker_present(),
            outside_agent_tree: observed.agent_trees().is_empty(),
        }
    }
    #[cfg(feature = "runtime")]
    pub(crate) fn passes(&self, peer_owner: &str) -> bool {
        !self.os_owner.is_empty()
            && self.os_owner == peer_owner
            && self.stdin_console
            && self.stdout_console
            && !self.session_present
            && !self.provider_marker_present
            && self.outside_agent_tree
    }
}
