//! CLI console observation carried over an authenticated owner connection.
//! This is a mistake/drift guard, not authority against hostile same-user code.
//! The host independently rechecks the native peer's owner and managed ancestry.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
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
    #[cfg(feature = "runtime")]
    pub(crate) fn refusal_reason(&self, peer_owner: &str) -> String {
        let cause = if !self.stdout_console {
            "stdout is redirected, captured or otherwise not attached to a console/TTY"
        } else if !self.stdin_console {
            "stdin is redirected or otherwise not attached to a console/TTY"
        } else if self.os_owner.is_empty() || self.os_owner != peer_owner {
            "the observed CLI owner does not match the independent native peer owner"
        } else {
            "the CLI has a session/provider marker or is inside an agent tree"
        };
        format!(
            "{cause}; stdin_console={}, stdout_console={}, session_present={}, provider_marker_present={}, outside_agent_tree={}",
            self.stdin_console,
            self.stdout_console,
            self.session_present,
            self.provider_marker_present,
            self.outside_agent_tree,
        )
    }
}
