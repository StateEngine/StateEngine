use super::{IntegrationEffect, LaunchOutput, NextStep};
use crate::config_policy::{Provider, ResolvedProfile};
use schemars::JsonSchema;
use se_types::{AgentId, HumanId, IdempotencyKey, ProjectId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ProjectView {
    pub id: ProjectId,
    pub name: String,
    pub root: String,
    pub registered_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<GitView>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct OwnerView {
    pub human_id: HumanId,
    pub os_user: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct GitView {
    pub head: Option<String>,
    pub branch: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commits: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uncommitted: Option<bool>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RepositoryView {
    pub root: String,
    pub git: Option<GitView>,
    pub files_touched: u32,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum InitOutcome {
    Created,
    Adopted,
    AlreadyPresent,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum IdentityOutcome {
    Created,
    Existing,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct InitialAgent {
    pub id: AgentId,
    pub name: String,
    pub outcome: IdentityOutcome,
    pub provider: Provider,
    pub model: Option<String>,
    pub permission_profile: ResolvedProfile,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct InitProfile {
    pub schema: String,
    pub project: ProjectId,
    pub repo_root: String,
    pub registry_root: String,
    pub keys_dir: String,
    pub human_id: HumanId,
    pub agent_id: AgentId,
    pub native_server_port: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct InitOutput {
    pub idempotency_key: IdempotencyKey,
    pub outcome: InitOutcome,
    pub project: ProjectView,
    pub repo: RepositoryView,
    pub owner: OwnerView,
    pub home: String,
    pub agent: InitialAgent,
    pub profile: InitProfile,
    pub integrations: Vec<IntegrationEffect>,
    pub changed: Vec<String>,
    pub next: NextStep,
    pub launch: Option<LaunchOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import_hint: Option<String>,
}
