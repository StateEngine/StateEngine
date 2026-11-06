//! A phone action is a single-use grant, never a general machine credential.
use super::*;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeTarget {
    pub principal_revision: u64,
    pub profile_revision: u64,
    pub previous_session_event: Option<se_types::EventId>,
    pub conversation: Option<se_types::ProviderSessionId>,
    pub configuration: [u8; 32],
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeAction {
    pub id: ActionId,
    pub connection: ChannelId,
    pub binding_revision: u64,
    pub message: MessageId,
    pub target: ResumeTarget,
    pub subject: i64,
    pub private_chat: i64,
    pub expires_at_us: i64,
    pub state: String,
    pub code: Option<String>,
}
