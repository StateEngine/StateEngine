//! Operation metadata shared by the CLI, schemas and authenticated tool catalogue.
use se_types::ApiVersion;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Auth { Owner, Session, Either }
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanPolicy { Never, Always, ConfigKey }
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect { Read, Write, Custody }
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope { None, Home, Project, ProjectOrAll, Session }
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeNeed { None, HostForWrites, Host, HostAutoStart }
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Feature { Core, Atlas }
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Family { pub name: &'static str, pub major: u16 }
impl Family {
    pub fn schema(self) -> String { format!("{}/v{}", self.name, self.major) }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HumanKind {
    Version, Help, Schema, Principal, Init, Status, Diagnosis, Repair, Bundle,
    ConfigValue, ConfigReceipt, ConfigPage, RuntimeStart, RuntimeStop, AgentPage,
    AgentReceipt, AgentStatus, Launch, Stop, Wake, Resume, WorkingState,
    WorkingStateReceipt, SearchPage, HistoryPage, Event, MessageReceipt,
    MessagePage, MessageRead, DispositionReceipt, DecisionReceipt, DecisionPage,
    Decision, SessionBegin, SessionContext, TurnReceipt, SessionEnd, Hook,
    Restore, CredentialRotation, Uninstall, Import, Erasure, Remove, CodeHits,
    CodeRefs, Impact, CodeChanges, Outline, Mcp, HeaderMap,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "flag", rename_all = "snake_case")]
pub enum Selector { Always, Flag(&'static str) }
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CliExposure {
    Leaf { path: &'static [&'static str], hidden: bool, select: Selector },
    RootFlag { flag: &'static str },
    None { reason: &'static str },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum McpExposure {
    Tool { name: &'static str, title: &'static str, description: &'static str },
    None { reason: &'static str },
}
/// A branch changes authority/exposure together, never just the human-policy bit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct VariantPolicy {
    pub selector: &'static str,
    pub auth: Auth,
    pub human_only: HumanPolicy,
    pub effect: Effect,
    pub mcp: McpExposure,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct OpMeta {
    pub name: &'static str,
    pub cli: CliExposure,
    pub mcp: McpExposure,
    pub auth: Auth,
    pub anonymous: bool,
    pub human_only: HumanPolicy,
    pub effect: Effect,
    pub variants: &'static [VariantPolicy],
    pub scope: Scope,
    pub runtime: RuntimeNeed,
    pub feature: Feature,
    pub family: Family,
    pub human: HumanKind,
    pub since: ApiVersion,
    pub journeys: &'static [&'static str],
}
impl OpMeta {
    pub fn variant(&self, selector: &str) -> Option<&VariantPolicy> {
        self.variants.iter().find(|branch| branch.selector == selector)
    }
    pub const fn mutates(&self) -> bool { !matches!(self.effect, Effect::Read) }
}
