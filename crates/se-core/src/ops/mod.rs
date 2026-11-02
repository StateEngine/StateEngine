//! The operation list for the executable wave-one surface. Later waves add their
//! production operations here; no placeholder handlers or phantom tools are exposed.
pub mod administration;
pub mod agent;
pub mod agent_launch;
pub mod agent_stop;
pub mod process_commit;
pub mod process_plan;
pub mod project_remove;
pub mod session_commit;
pub mod stop_plan;
pub use agent_launch::{AgentLaunch, LaunchResult};
pub use agent_stop::{AgentStop, StopResult};
pub use project_remove::{ProjectRemove, RemoveResult};
pub mod agent_config;
pub mod agent_config_receipt;
mod agent_session;
pub mod agent_status;
mod cli;
pub mod decision;
pub mod decision_show;
pub use decision_show::{DecisionDetail, DecisionOutput, DecisionShow, DecisionTransition};
pub mod event;
pub mod history;
pub use history::{HistoryList, HistoryPage};
pub mod hook;
pub mod inputs;
pub mod installation;
pub mod listing;
pub mod message;
pub use listing::{AgentList, AgentPage};
mod meta;
pub mod outputs;
pub mod project;
pub mod receipt;
pub mod status;
pub use crate::commit::{MessageSend, WorkingStateSet};
use crate::registry::*;
pub use cli::{
    CliSelections, CommonArgs, cli_command, from_matches, from_matches_with_key, selected_meta,
};
pub use event::{EventOutput, EventRead, HistoryEvent};
pub use hook::{HookClaude, HookEvent, HookResult};
pub use inputs::*;
pub use meta::{
    McpTool, decode_operation, decode_tool, mcp_tools, metadata_output, schema_catalogue,
};
pub use outputs::*;
mod output_sum;
pub use administration::*;
pub use output_sum::AnyOutput;
use schemars::JsonSchema;
use se_types::{API_VERSION, IdempotencyKey, Result};
use serde::Serialize;

#[derive(Clone, Debug, Serialize, serde::Deserialize, JsonSchema)]
pub struct Envelope<T> {
    schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<OutputDiagnostics>,
    /// Transient obligation after a known successful commit, never an unknown outcome.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub maintenance_pending: bool,
    #[serde(flatten)]
    pub value: T,
}
impl<T> Envelope<T> {
    fn new(family: Family, value: T) -> Self {
        Self {
            schema: family.schema(),
            diagnostics: None,
            maintenance_pending: false,
            value,
        }
    }
}

macro_rules! ops {
    ($( $variant:ident => $input:ty, $output:ty,
        ($name:literal, $cli:expr, $mcp:expr, $auth:ident, $anonymous:literal, $human:ident, $effect:ident, $scope:ident, $runtime:ident, $family:literal, $render:ident, $journeys:expr); )+) => {
        #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
        #[serde(tag="op",content="input",deny_unknown_fields)]
        pub enum AnyOp { $( #[serde(rename=$name)] $variant($input), )+ }
        $(impl $input { pub const META: OpMeta = OpMeta {
            name:$name, cli:$cli, mcp:$mcp, auth:Auth::$auth, anonymous:$anonymous,
            human_only:HumanPolicy::$human, effect:Effect::$effect, variants:&[],
            scope:Scope::$scope, runtime:RuntimeNeed::$runtime, feature:Feature::Core,
            family:Family { name:$family, major:1 }, human:HumanKind::$render,
            since:API_VERSION, journeys:$journeys,
        }; })+
        pub static CATALOGUE: &[&OpMeta] = &[ $( &<$input>::META, )+ ];
        impl AnyOp {
            pub fn meta(&self) -> &'static OpMeta { match self { $( Self::$variant(_)=><$input>::META_REF(), )+ } }
            pub fn validate(&self) -> Result<()> { match self { $( Self::$variant(value)=>value.validate(), )+ } }
            pub fn input_schema(&self) -> serde_json::Value { match self { $( Self::$variant(_)=>schemars::schema_for!($input).to_value(), )+ } }
        }
        $(impl $input { #[allow(non_snake_case)] fn META_REF() -> &'static OpMeta { &Self::META } })+
        pub(crate) fn schemas(name:&str) -> Option<(serde_json::Value,serde_json::Value)> {
            match name { $( $name=>{
                let mut output=schemars::schema_for!(Envelope<$output>).to_value();
                if let Some(properties)=output.get_mut("properties").and_then(serde_json::Value::as_object_mut) {
                    properties.insert("schema".into(),serde_json::json!({"const":<$input>::META.family.schema()}));
                }
                Some((schemars::schema_for!($input).to_value(),output))
            }, )+ _=>None }
        }
    }
}
const fn leaf(path: &'static [&'static str]) -> CliExposure {
    CliExposure::Leaf {
        path,
        hidden: false,
        select: Selector::Always,
    }
}
const fn no_mcp(reason: &'static str) -> McpExposure {
    McpExposure::None { reason }
}
const fn tool(name: &'static str, title: &'static str, description: &'static str) -> McpExposure {
    McpExposure::Tool {
        name,
        title,
        description,
    }
}
ops! {
    MetaVersion => MetaVersion, VersionOutput, ("meta.version",CliExposure::RootFlag { flag:"version" },no_mcp("Installed CLI metadata is not an agent task."),Either,true,Never,Read,None,None,"se.version",Version,&["J1"]);
    MetaHelp => MetaHelp, HelpOutput, ("meta.help",leaf(&["help"]),no_mcp("MCP descriptions derive from the same catalogue."),Either,true,Never,Read,None,None,"se.help",Help,&["J1"]);
    MetaSchema => MetaSchema, SchemaCatalogue, ("meta.schema",leaf(&["schema"]),no_mcp("MCP tools/list exposes the generated schemas."),Either,true,Never,Read,None,None,"se.schema-catalogue",Schema,&["J1"]);
    ProjectInit => ProjectInit, InitOutput, ("project.init",leaf(&["init"]),no_mcp("Owner setup registers the managed workspace."),Owner,false,Never,Write,Home,None,"se.init",Init,&["J2"]);
    ProjectStatus => ProjectStatus, StatusOutput, ("project.status",leaf(&["status"]),tool("stateengine_status","Project status","Read setup, agent and runtime facts without changing state."),Either,false,Never,Read,ProjectOrAll,None,"se.status",Status,&["J1","J2"]);
    EventRead => EventRead, EventOutput, ("history.event_read",CliExposure::Leaf {path:&["history"],hidden:false,select:Selector::Flag("event")},tool("stateengine_event_read","Read a committed event","Read one committed event by ID in the authorized project, with its public payload and provenance."),Either,false,Never,Read,Project,None,"se.event",Event,&["E3","J3","J4"]);
    HistoryList => HistoryList, HistoryPage, ("history.list",leaf(&["history"]),no_mcp("Sessions use event_read for exact public records; owner CLI history is read-only inspection."),Either,false,Never,Read,Project,None,"se.history-page",HistoryPage,&["J3"]);
    MessageSend => MessageSend, MessageOutput, ("message.send",leaf(&["msg","send"]),tool("stateengine_msg_send","Send a message","Commit a message to another project agent or owner; committed does not mean read."),Either,false,Never,Write,Project,HostForWrites,"se.message-receipt",MessageReceipt,&["J4"]);
    MessageList => MessageList, MessagePage, ("message.list",leaf(&["msg","list"]),tool("stateengine_msg_list","List your messages","List authorized messages with explicit completeness; listing never marks mail read."),Either,false,Never,Read,Project,None,"se.message-page",MessagePage,&["J4"]);
    WorkingStateGet => WorkingStateGet, WorkingStateOutput, ("working_state.get",leaf(&["working-state"]),tool("stateengine_working_state_get","Read working state","Read your saved note and entity revision."),Either,false,Never,Read,Session,None,"se.working-state",WorkingState,&["J3"]);
    WorkingStateSet => WorkingStateSet, WorkingStateReceipt, ("working_state.set",leaf(&["working-state","set"]),tool("stateengine_working_state_set","Replace working state","Replace your note with the revision you read or absent for the first write."),Either,false,Never,Write,Session,HostForWrites,"se.working-state-receipt",WorkingStateReceipt,&["J3"]);
    HookClaude => HookClaude, HookResult, ("hook.claude",CliExposure::Leaf {path:&["hook","claude"],hidden:true,select:Selector::Always},no_mcp("Provider hooks use authenticated native stdin and pinned-source capture."),Session,false,Never,Custody,Session,HostAutoStart,"se.hook-result",Hook,&["E3","J3"]);
    RuntimeUp => RuntimeUp, RuntimeStart, ("runtime.up",leaf(&["up"]),no_mcp("Runtime custody is an owner operation."),Owner,false,Never,Custody,Home,HostAutoStart,"se.runtime-start",RuntimeStart,&["J3"]);
    RuntimeDown => RuntimeDown, RuntimeStop, ("runtime.down",leaf(&["down"]),no_mcp("Runtime custody is an owner operation."),Owner,false,Never,Custody,Home,None,"se.runtime-stop",RuntimeStop,&["J3"]);
    Uninstall => Uninstall, UninstallOutput, ("installation.uninstall",leaf(&["uninstall"]),no_mcp("Installation removal requires the owner at a human terminal."),Owner,false,Always,Custody,Home,None,"se.uninstall",Uninstall,&["J5"]);
    AgentCreate => AgentCreate, AgentReceipt, ("agent.create",leaf(&["agent","add"]),tool("stateengine_agent_create","Create an agent","Create a durable agent identity and safe saved profile without launching a process; sessions require their current create grant."),Either,false,Never,Write,Project,HostForWrites,"se.agent-receipt",AgentReceipt,&["E3","J2","J4"]);
    AgentList => AgentList, AgentPage, ("agent.list",leaf(&["agent","list"]),no_mcp("Owner overview; bound agents use status for their own saved identity."),Owner,false,Never,Read,Project,None,"se.agent-page",AgentPage,&["J2","J3"]);
    AgentLaunch => AgentLaunch, LaunchResult, ("agent.launch",leaf(&["launch"]),tool("stateengine_agent_launch","Launch an agent","Launch your own saved agent or a directly created agent you currently control; readiness and process custody are witnessed."),Either,false,Never,Custody,Project,HostAutoStart,"se.launch",Launch,&["J2","J3"]);
    AgentStop => AgentStop, StopResult, ("agent.stop",leaf(&["stop"]),tool("stateengine_agent_stop","Stop an agent","Stop your own agent or a directly created agent you currently control; returns the command that resumes its saved conversation."),Either,false,Never,Custody,ProjectOrAll,HostAutoStart,"se.stop",Stop,&["J3","J5"]);
    ProjectRemove => ProjectRemove, RemoveResult, ("project.remove",leaf(&["remove"]),no_mcp("Project removal requires the verified owner at a human terminal."),Owner,false,Always,Custody,ProjectOrAll,HostAutoStart,"se.remove",Remove,&["J5"]);
    AgentShow => AgentShow, AgentStatusOutput, ("agent.show",leaf(&["agent","show"]),no_mcp("This owner CLI read inspects saved agent metadata."),Owner,false,Never,Read,Project,None,"se.agent-status",AgentStatus,&["E3","J2"]);
    ConfigGet => ConfigGet, ConfigValueOutput, ("config.get",leaf(&["config","get"]),no_mcp("Saved agent settings are inspected by the owner CLI."),Owner,false,Never,Read,Project,None,"se.config-value",ConfigValue,&["E3"]);
    ConfigSet => ConfigSet, AgentConfigReceipt, ("config.set",leaf(&["config","set"]),no_mcp("Saved agent metadata changes are owner CLI operations."),Owner,false,ConfigKey,Write,Project,HostForWrites,"se.config-receipt",ConfigReceipt,&["E3"]);
    DecisionShow => DecisionShow, DecisionOutput, ("decision.show",leaf(&["decision","show"]),no_mcp("Decision detail is inspected through the project CLI."),Either,false,Never,Read,Project,None,"se.decision",Decision,&["E3","J4"]);
    DecisionPropose => DecisionPropose, DecisionReceipt, ("decision.propose",leaf(&["decide"]),tool("stateengine_decision_propose","Propose a decision","Save a proposal for the owner; a proposal does not ratify itself or become governing."),Either,false,Never,Write,Project,HostForWrites,"se.decision-receipt",DecisionReceipt,&["E3","J3","J4"]);
    DecisionRatify => DecisionRatify, DecisionReceipt, ("decision.ratify",leaf(&["decision","ratify"]),no_mcp("Only an independently verified owner terminal can ratify a proposal."),Owner,false,Always,Write,Project,HostForWrites,"se.decision-receipt",DecisionReceipt,&["E3","J4"]);
    DecisionReject => DecisionReject, DecisionReceipt, ("decision.reject",leaf(&["decision","reject"]),no_mcp("Only an independently verified owner terminal can reject a proposal."),Owner,false,Always,Write,Project,HostForWrites,"se.decision-receipt",DecisionReceipt,&["E3","J4"]);
    DecisionRetract => DecisionRetract, DecisionReceipt, ("decision.retract",leaf(&["decision","retract"]),no_mcp("Only an independently verified owner terminal can retract a decision."),Owner,false,Always,Write,Project,HostForWrites,"se.decision-receipt",DecisionReceipt,&["E3","J4"]);
    DecisionSupersede => DecisionSupersede, DecisionReceipt, ("decision.supersede",leaf(&["decision","supersede"]),no_mcp("Only an independently verified owner terminal can supersede a decision."),Owner,false,Always,Write,Project,HostForWrites,"se.decision-receipt",DecisionReceipt,&["E3","J4"]);
}
impl AnyOp {
    /// Shared per-operation/per-key classification for CLI and host admission.
    pub fn requires_human_terminal(&self) -> Result<bool> {
        if matches!(self, Self::AgentStop(input) if input.release) {
            return Ok(true);
        }
        match self.meta().human_only {
            HumanPolicy::Always => Ok(true),
            HumanPolicy::Never => Ok(false),
            HumanPolicy::ConfigKey => match self {
                Self::ConfigSet(input) => {
                    Ok(crate::config_policy::key_metadata(&input.key)?.human_only)
                }
                _ => Err(crate::scope::unreadable(
                    "human-presence policy",
                    "config-key policy has no registered key selector",
                )),
            },
        }
    }
    pub fn idempotency_key(&self) -> Option<&IdempotencyKey> {
        match self {
            Self::ProjectInit(v) => Some(&v.idempotency_key),
            Self::MessageSend(v) => Some(&v.idempotency_key),
            Self::WorkingStateSet(v) => Some(&v.idempotency_key),
            Self::RuntimeUp(v) => Some(&v.idempotency_key),
            Self::RuntimeDown(v) => Some(&v.idempotency_key),
            Self::Uninstall(v) => Some(&v.idempotency_key),
            Self::AgentCreate(v) => Some(&v.idempotency_key),
            Self::AgentLaunch(v) => Some(&v.idempotency_key),
            Self::AgentStop(v) => Some(&v.idempotency_key),
            Self::ProjectRemove(v) => Some(&v.idempotency_key),
            Self::ConfigSet(v) => Some(&v.idempotency_key),
            Self::DecisionPropose(v) => Some(&v.idempotency_key),
            Self::DecisionRatify(v) => Some(&v.idempotency_key),
            Self::DecisionReject(v) => Some(&v.idempotency_key),
            Self::DecisionRetract(v) => Some(&v.idempotency_key),
            Self::DecisionSupersede(v) => Some(&v.idempotency_key),
            _ => None,
        }
    }
    pub fn resolve_stdin(
        &mut self,
        read: &mut dyn FnMut(String, &str, usize) -> Result<String>,
    ) -> Result<()> {
        match self {
            Self::MessageSend(v) => {
                v.body = read(v.body.clone(), "body", se_types::MESSAGE_BODY_MAX_BYTES)?
            }
            Self::WorkingStateSet(v) => {
                v.text = read(v.text.clone(), "text", se_types::WORKING_STATE_MAX_BYTES)?
            }
            Self::DecisionPropose(v) => {
                v.statement = read(v.statement.clone(), "statement", 8192)?;
                if let Some(value) = &mut v.rationale {
                    *value = read(value.clone(), "rationale", 2048)?;
                }
            }
            Self::DecisionReject(v) => v.reason = read(v.reason.clone(), "reason", 2048)?,
            Self::DecisionRetract(v) => v.reason = read(v.reason.clone(), "reason", 2048)?,
            _ => (),
        }
        self.validate()
    }
}
impl AnyOutput {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Uninstall(v) if !v.value.complete => 2,
            Self::AgentStop(v) if !v.value.complete => 2,
            Self::ProjectRemove(v) if !matches!(v.value.outcome.as_str(), "removed" | "absent") => 2,
            Self::RuntimeDown(v) if !v.value.complete => 2,
            Self::RuntimeUp(v) if v.value.state == "pending" => 2,
            Self::EventRead(v) => match &v.value {
                EventOutput::Present(_) => 0,
                EventOutput::Other(value) => value.exit_code(),
            },
            Self::WorkingStateGet(v) => v.value.value.exit_code(),
            Self::ConfigGet(v) => v.value.value.exit_code(),
            Self::DecisionShow(v) => v.value.decision.exit_code(),
            Self::AgentShow(v) => v.value.agent.exit_code(),
            Self::AgentList(v) => v.value.page.window().exit_code(false),
            Self::HistoryList(v) => v.value.page.window().exit_code(false),
            Self::ProjectStatus(v) => {
                let project = v.value.project.exit_code();
                if project != 0 {
                    return project;
                }
                if matches!(v.value.setup.state, SetupState::Unreadable) {
                    return 3;
                }
                v.value
                    .agents
                    .as_ref()
                    .map(|page| page.window().exit_code(false))
                    .unwrap_or(0)
                    .max(
                        v.value
                            .projects
                            .as_ref()
                            .map(|page| page.window().exit_code(false))
                            .unwrap_or(0),
                    )
            }
            Self::MessageList(v) => {
                let page = &v.value.page;
                let unread = page
                    .items()
                    .iter()
                    .filter(|row| row.disposition.state == "unread")
                    .count() as u64;
                if page.items().iter().any(|row| {
                    row.unreadable.is_some() || (v.value.view.full && !row.body.complete)
                }) || (v.value.view.r#box == "inbox"
                    && v.value.unread_total.is_none_or(|total| total > unread))
                {
                    2
                } else {
                    page.window().exit_code(false)
                }
            }
            _ => 0,
        }
    }
}

const fn equal(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}
const fn same_path(a: &[&str], b: &[&str]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if !equal(a[i], b[i]) {
            return false;
        }
        i += 1;
    }
    true
}
// These are source mirror invariants, not a separately maintained catalogue count.
const _: () = {
    let mut i = 0;
    while i < CATALOGUE.len() {
        let row = CATALOGUE[i];
        assert!(!row.name.is_empty(), "operation names are nonempty");
        if let CliExposure::None { reason } = row.cli {
            assert!(reason.len() >= 12, "omitted CLI exposure needs a reason");
        }
        match row.mcp {
            McpExposure::None { reason } => {
                assert!(reason.len() >= 12, "omitted MCP exposure needs a reason")
            }
            McpExposure::Tool {
                name,
                title,
                description,
            } => {
                assert!(name.len() > 12, "MCP tool names start with stateengine_");
                let prefix = b"stateengine_";
                let bytes = name.as_bytes();
                let mut p = 0;
                while p < prefix.len() {
                    assert!(
                        bytes[p] == prefix[p],
                        "MCP tool names start with stateengine_"
                    );
                    p += 1;
                }
                while p < bytes.len() {
                    assert!(
                        (bytes[p] >= b'a' && bytes[p] <= b'z')
                            || (bytes[p] >= b'0' && bytes[p] <= b'9')
                            || bytes[p] == b'_',
                        "MCP tool names use lowercase ASCII"
                    );
                    p += 1;
                }
                assert!(
                    !title.is_empty() && !description.is_empty(),
                    "exposed tools need readable descriptions"
                );
                assert!(
                    !matches!(row.auth, Auth::Owner),
                    "owner operations have no MCP tool"
                );
            }
        }
        if row.anonymous {
            assert!(
                equal(row.name, "meta.version")
                    || equal(row.name, "meta.help")
                    || equal(row.name, "meta.schema"),
                "only installed metadata is anonymous"
            );
        }
        if matches!(row.human_only, HumanPolicy::Always | HumanPolicy::ConfigKey) {
            assert!(
                matches!(row.auth, Auth::Owner) && matches!(row.mcp, McpExposure::None { .. }),
                "human operations are owner CLI only"
            );
        }
        let mut j = 0;
        while j < i {
            let before = CATALOGUE[j];
            assert!(
                !equal(row.name, before.name),
                "operation names must be unique"
            );
            if let (McpExposure::Tool { name: a, .. }, McpExposure::Tool { name: b, .. }) =
                (row.mcp, before.mcp)
            {
                assert!(!equal(a, b), "MCP tool names must be unique");
            }
            if let (
                CliExposure::Leaf {
                    path: a,
                    select: a_select,
                    ..
                },
                CliExposure::Leaf {
                    path: b,
                    select: b_select,
                    ..
                },
            ) = (row.cli, before.cli)
                && same_path(a, b)
            {
                match (a_select, b_select) {
                    (Selector::Always, Selector::Always) => {
                        panic!("CLI leaf paths require distinct selectors")
                    }
                    (Selector::Flag(a), Selector::Flag(b)) => {
                        assert!(!equal(a, b), "CLI leaf paths require distinct selectors")
                    }
                    _ => (),
                }
            }
            j += 1;
        }
        i += 1;
    }
};
