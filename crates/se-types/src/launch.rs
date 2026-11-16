//! Explicit provider-conversation selection shared by local and remote launch.
use crate::{Provider, ProviderSessionId, Read, Result, SessionId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Omit this value for a fresh conversation. `true` resumes the most recent
/// saved conversation; a session ID selects that saved session's conversation.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum ResumeSelection {
    Latest(bool),
    Session(SessionId),
}

impl ResumeSelection {
    pub fn from_cli(value: Option<String>) -> Result<Option<Self>> {
        value
            .map(|value| {
                if value == "latest" {
                    Ok(Self::Latest(true))
                } else {
                    Ok(Self::Session(value.parse()?))
                }
            })
            .transpose()
    }
    pub fn requested(selection: Option<&Self>) -> bool {
        matches!(selection, Some(Self::Latest(true) | Self::Session(_)))
    }
}

/// Settings and observations for the original launch, including receipt replays.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LaunchDetails {
    pub provider: Provider,
    pub model: Option<String>,
    pub permission_profile: String,
    pub permission: String,
    pub network: bool,
    pub resumed: bool,
    pub conversation: Read<ProviderSessionId>,
    /// Connection observed at launch; not proof that a message was read or acted on.
    pub mail_notifications: Read<bool>,
}
impl LaunchDetails {
    pub fn unobserved_mail() -> Read<bool> {
        Read::Unknown {
            what: "this launch receipt predates mail connection reporting".into(),
        }
    }
}
