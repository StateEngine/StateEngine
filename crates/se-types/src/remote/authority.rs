use crate::{
    AgentId, Generation, ProjectId, RemoteDeviceId, RemoteGrantId, RemotePrincipalId, Result,
    SeError, SessionId, Sha256, StoreId, UnixMicros,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Digest of the protected machine identity; independent of OS names and addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct RemoteHostId(pub Sha256);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct CredentialDigest(pub [u8; 32]);

#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RemoteVerb {
    List,
    Watch,
    Send,
    Launch,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteTarget {
    pub project: ProjectId,
    pub agent: AgentId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteScope {
    pub targets: Vec<RemoteTarget>,
    pub verbs: Vec<RemoteVerb>,
}
impl RemoteScope {
    pub fn validate(&self) -> Result<()> {
        super::request::validate_targets(&self.targets, true)?;
        if self.verbs.is_empty()
            || self.verbs.len() > 3
            || self.verbs.contains(&RemoteVerb::Launch)
            || self.verbs.iter().collect::<BTreeSet<_>>().len() != self.verbs.len()
        {
            return Err(SeError::invalid(
                "remote verbs",
                "a nonempty set of list/watch/send",
            ));
        }
        Ok(())
    }
    pub fn allows(&self, verb: RemoteVerb, target: &RemoteTarget) -> bool {
        self.verbs.contains(&verb) && (self.targets.is_empty() || self.targets.contains(target))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RemoteSubject {
    Machine { host: RemoteHostId },
}

/// A public per-request broker assertion, not a locally verified session capability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteSourceSession {
    pub host: RemoteHostId,
    pub project: ProjectId,
    pub agent: AgentId,
    pub session: SessionId,
    pub generation: Generation,
}
impl RemoteSubject {
    pub fn admits_source(&self, source: Option<&RemoteSourceSession>) -> bool {
        match (self, source) {
            (Self::Machine { host }, Some(source)) => *host == source.host,
            (Self::Machine { .. }, None) => true,
        }
    }
}

/// Persisted attribution is data; only the authenticated adapter may admit it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteAttribution {
    pub host: RemoteHostId,
    pub store: StoreId,
    pub principal: RemotePrincipalId,
    pub grant: RemoteGrantId,
    pub device: RemoteDeviceId,
    pub authority_revision: u64,
    pub source: Option<RemoteSourceSession>,
}

/// Public machine-session facts; private connection material is stored separately.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MachineSession {
    pub host: RemoteHostId,
    pub grant: RemoteGrantId,
    pub device: RemoteDeviceId,
    pub subject: RemoteSubject,
    pub scope: RemoteScope,
    pub authority_revision: u64,
    pub expires_at: UnixMicros,
}

/// A mailbox address survives provider-session and host-process restarts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RemoteAgentAddress {
    pub host: RemoteHostId,
    pub project: ProjectId,
    pub agent: AgentId,
}
impl RemoteAgentAddress {
    /// Public selector used by ordinary mail; authority still comes from the
    /// exact received message and its authenticated source attribution.
    pub fn selector(&self) -> String {
        format!("{}/{}/{}", self.host.0.hex(), self.project, self.agent)
    }
}
impl RemoteSourceSession {
    pub fn address(&self) -> RemoteAgentAddress {
        RemoteAgentAddress {
            host: self.host,
            project: self.project.clone(),
            agent: self.agent.clone(),
        }
    }
}
