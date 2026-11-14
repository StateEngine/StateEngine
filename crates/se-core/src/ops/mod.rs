//! The operation list for the executable wave-one surface. Later waves add their
//! production operations here; no placeholder handlers or phantom tools are exposed.
pub mod administration;
pub mod atlas;
pub mod atlas_hook;
pub use atlas::*;
pub use atlas_hook::{AtlasAugment, AtlasHookOutput, AtlasHookTarget};
pub mod client;
pub use client::ClientWatchCall;
pub mod remote;
pub use remote::{
    RemoteLaunchCall, RemoteLaunchOutput, RemoteListCall, RemoteListOutput, RemotePrepareSendCall,
    RemoteSendCall, RemoteSendOutput, RemoteSendPreparation, RemoteWatchCall, RemoteWatchOutput,
};
pub mod continuity;
pub use continuity::{Resume, ResumeOutput, SessionContextOutput, SessionContextRequest};
pub mod adoption;
pub mod agent;
pub mod agent_launch;
pub mod agent_stop;
pub mod agent_wake;
pub mod process_commit;
pub mod process_plan;
pub mod project_remove;
pub mod remove_commit;
pub mod session_commit;
pub mod session_reference;
pub mod stop_plan;
pub use agent_launch::{AgentLaunch, LaunchPending, LaunchPendingState, LaunchReply, LaunchResult};
pub use agent_stop::{AgentStop, StopResult};
pub use agent_wake::{AgentWake, WakeResult};
pub use project_remove::{ProjectRemove, RemoveResult};
pub mod agent_config;
pub mod agent_config_receipt;
mod agent_session;
pub use agent_session::{process_from_record, unobserved_session};
pub use cli::parse_remote_target;
pub mod agent_status;
mod cli;
pub mod config_listing;
pub(crate) use cli::command_name;
pub mod diagnostic_bundle;
pub use diagnostic_bundle::{DiagnosticBundle, DiagnosticBundleOutput};
pub mod doctor;
pub use doctor::{Diagnosis, DoctorInspect, DoctorRepair, RepairOutput};
pub mod event;
mod guide;
pub mod history;
pub use guide::{GuideOutput, GuideTopicSummary, MetaGuide};
pub use history::{HistoryList, HistoryPage};
pub mod identity;
pub use identity::{
    IdentityWhoami, PrincipalAgent, PrincipalBinding, PrincipalOutput, PrincipalProject,
    PrincipalSession,
};
pub mod hook;
pub mod inbox;
pub mod inputs;
pub mod queued_input;
pub mod transcript;
pub use inbox::MessageInbox;
pub mod installation;
#[cfg(feature = "import")]
pub mod store_import;
#[cfg(feature = "import")]
pub use store_import::{ImportNode, ImportReceipt};
pub mod listing;
pub mod mail;
pub mod message_mark;
pub use message_mark::{
    DispositionReceipt, MessageAck, MessageDismiss, MessageRead, MessageReadOutput,
};
pub mod message;
pub use listing::{AgentList, AgentPage};
pub mod mcp_identity;
mod mcp_schema;
mod meta;
pub mod outputs;
pub mod project;
pub mod receipt;
pub mod status;
pub use crate::commit::{MessageSend, WorkingStateSet};
use crate::registry::*;
pub use cli::{
    AgentCommand, CliSelections, CommonArgs, cli_command, diagnostic_word, from_matches,
    from_matches_with_key, selected_meta,
};
pub use event::{EventOutput, EventRead, HistoryEvent};
pub use hook::{HookClaude, HookEvent, HookResult};
pub use inputs::*;
pub use message::{channel_reply_instruction, remote_reply_from};
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
    /// Failed maintenance after a known commit; healthy scheduled work is omitted.
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
    ($( $( #[$cfg:meta] )* $variant:ident => $input:ty, $output:ty,
        ($name:literal, $cli:expr, $mcp:expr, $auth:ident, $anonymous:literal, $human:ident, $effect:ident, $scope:ident, $runtime:ident, $family:literal, $render:ident, $journeys:expr); )+) => {
        #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
        #[serde(tag="op",content="input",deny_unknown_fields)]
        pub enum AnyOp { $( $( #[$cfg] )* #[serde(rename=$name)] $variant($input), )+ }
        $( $( #[$cfg] )* impl $input { pub const META: OpMeta = OpMeta {
            name:$name, cli:$cli, mcp:$mcp, auth:Auth::$auth, anonymous:$anonymous,
            human_only:HumanPolicy::$human, effect:Effect::$effect, variants:&[],
            scope:Scope::$scope, runtime:RuntimeNeed::$runtime, feature:operation_feature($name),
            family:Family { name:$family, major:1 }, human:HumanKind::$render,
            since:API_VERSION, journeys:$journeys,
        }; })+
        pub static CATALOGUE: &[&OpMeta] = &[ $( $( #[$cfg] )* &<$input>::META, )+ ];
        impl AnyOp {
            pub fn meta(&self) -> &'static OpMeta { match self { $( $( #[$cfg] )* Self::$variant(_)=><$input>::META_REF(), )+ } }
            pub fn validate(&self) -> Result<()> { match self { $( $( #[$cfg] )* Self::$variant(value)=>value.validate(), )+ } }
            pub fn input_schema(&self) -> serde_json::Value { match self { $( $( #[$cfg] )* Self::$variant(_)=>advertised_input_schema(schemars::schema_for!($input).to_value()), )+ } }
        }
        $( $( #[$cfg] )* impl $input { #[allow(non_snake_case)] fn META_REF() -> &'static OpMeta { &Self::META } })+
        pub(crate) fn input_schema(name:&str) -> Option<serde_json::Value> {
            match name { $( $( #[$cfg] )* $name=>Some(advertised_input_schema(schemars::schema_for!($input).to_value())), )+ _=>None }
        }
        pub fn schemas(name:&str) -> Option<(serde_json::Value,serde_json::Value)> {
            match name { $( $( #[$cfg] )* $name=>{
                let mut output=schemars::schema_for!(Envelope<$output>).to_value();
                if let Some(properties)=output.get_mut("properties").and_then(serde_json::Value::as_object_mut) {
                    properties.insert("schema".into(),serde_json::json!({"const":<$input>::META.family.schema()}));
                }
                Some((input_schema(name)?,output))
            }, )+ _=>None }
        }
    }
}
const fn operation_feature(name: &str) -> Feature {
    let bytes = name.as_bytes();
    if bytes.len() > 6
        && bytes[0] == b'a'
        && bytes[1] == b't'
        && bytes[2] == b'l'
        && bytes[3] == b'a'
        && bytes[4] == b's'
        && bytes[5] == b'.'
    {
        Feature::Atlas
    } else {
        Feature::Core
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
/// Unit-struct inputs have no fields, so schemars emits a root `type: "null"`
/// that no MCP client can register as tool arguments. Advertise the object
/// schema instead; `mcp_identity::describe` supplies the ordinary optional
/// caller properties on the MCP surface.
fn advertised_input_schema(mut schema: serde_json::Value) -> serde_json::Value {
    if let serde_json::Value::Object(root) = &mut schema
        && root.get("type") == Some(&serde_json::Value::String("null".into()))
    {
        root.insert("type".into(), serde_json::Value::String("object".into()));
    }
    schema
}
ops! {
    AtlasAugment => AtlasAugment, AtlasHookOutput, ("atlas.augment",CliExposure::None {reason:"Private native provider augmentation only."},no_mcp("The provider hook uses authenticated native IPC, never a model tool."),Session,false,Never,Read,Project,Host,"se.atlas-hook",Hook,&["J3"]);
    AtlasFind => AtlasFind, AtlasFindOutput, ("atlas.find",leaf(&["atlas","find"]),tool("stateengine_atlas_find","Atlas find","Search code and project records. regex matches live source; use (?i) to ignore case."),Either,false,Never,Read,Project,Host,"se.code-hits",CodeHits,&["J3"]);
    AtlasRefs => AtlasRefs, AtlasRefsOutput, ("atlas.refs",leaf(&["atlas","refs"]),tool("stateengine_atlas_refs","Atlas refs","Find references to a symbol or file, including labelled name-only candidates."),Either,false,Never,Read,Project,Host,"se.code-refs",CodeRefs,&["J3"]);
    AtlasImpact => AtlasImpact, AtlasImpactOutput, ("atlas.impact",leaf(&["atlas","impact"]),tool("stateengine_atlas_impact","Atlas impact","Follow bounded dependencies from a code or record target."),Either,false,Never,Read,Project,Host,"se.impact",Impact,&["J3"]);
    AtlasChanges => AtlasChanges, AtlasChangesOutput, ("atlas.changes",leaf(&["atlas","changes"]),tool("stateengine_atlas_changes","Atlas changes","Read changes since an Atlas cursor, observed commit or observation time."),Either,false,Never,Read,Project,Host,"se.code-changes",CodeChanges,&["J3"]);
    AtlasOutline => AtlasOutline, AtlasOutlineOutput, ("atlas.outline",leaf(&["atlas","outline"]),tool("stateengine_atlas_outline","Atlas outline","Read file declarations, source positions and linked records."),Either,false,Never,Read,Project,Host,"se.outline",Outline,&["J3"]);
    ClientWatch => ClientWatchCall, RemoteWatchOutput, ("client.watch",leaf(&["watch"]),no_mcp("Native human inspection; agents keep their admitted local or remote read tools."),Owner,false,Never,Read,Home,Host,"stateengine.remote-watch",RemoteWatch,&[]);
    RemotePrepareSend => RemotePrepareSendCall, RemoteSendPreparation, ("remote.prepare_send",CliExposure::None{reason:"Internal protected source IPC prepares CLI pending output; no remote capability or public tool."},no_mcp("MCP has only a final send result, never early pending output."),Either,false,Never,Read,Home,Host,"stateengine.remote-send-preparation",RemoteSend,&[]);
    RemoteList => RemoteListCall, RemoteListOutput, ("remote.list",leaf(&["remote","list"]),tool("stateengine_remote_list","List remote agents","List allowed remote agents; empty request.targets discovers all."),Either,false,Never,Read,Home,Host,"stateengine.remote-list",RemoteList,&[]);
    RemoteWatch => RemoteWatchCall, RemoteWatchOutput, ("remote.watch",leaf(&["remote","watch"]),tool("stateengine_remote_watch","Watch remote agents","Read a retained subscription; continue with returned cursors. Live items are provisional; wait_ms <= 30000."),Either,false,Never,Read,Home,Host,"stateengine.remote-watch",RemoteWatch,&[]);
    RemoteLaunch => RemoteLaunchCall, RemoteLaunchOutput, ("remote.launch",leaf(&["remote","launch"]),tool("stateengine_remote_launch","Launch a remote agent","Start an existing destination agent with its saved profile and explicit Owner consent. Send work through remote send after it runs. Retry pending or uncertain launches with the original key."),Either,false,Never,Write,Home,Host,"stateengine.remote-launch",RemoteLaunch,&[]);
    RemoteSend => RemoteSendCall, RemoteSendOutput, ("remote.send",leaf(&["remote","send"]),tool("stateengine_remote_send","Send remote direct mail","Send exact target/session mail. Retry uncertainty with identical key/body/target/session; commit is not delivery."),Either,false,Never,Write,Home,Host,"stateengine.remote-send",RemoteSend,&[]);
    MetaVersion => MetaVersion, VersionOutput, ("meta.version",CliExposure::RootFlag { flag:"version" },no_mcp("Installed CLI metadata is not an agent task."),Either,true,Never,Read,None,None,"se.version",Version,&["J1"]);
    MetaHelp => MetaHelp, HelpOutput, ("meta.help",leaf(&["help"]),no_mcp("MCP descriptions derive from the same catalogue."),Either,true,Never,Read,None,None,"se.help",Help,&["J1"]);
    MetaGuide => MetaGuide, GuideOutput, ("meta.guide",leaf(&["guide"]),tool("stateengine_help","Help guide","List short guide topics, or read one exact topic by name. Omit topic for the index."),Either,true,Never,Read,None,None,"se.guide",Guide,&["J1","J2","J3","J4","J5"]);
    MetaSchema => MetaSchema, SchemaCatalogue, ("meta.schema",leaf(&["schema"]),no_mcp("MCP tools/list exposes the generated schemas."),Either,true,Never,Read,None,None,"se.schema-catalogue",Schema,&["J1"]);
    IdentityWhoami => IdentityWhoami, PrincipalOutput, ("identity.whoami",CliExposure::None {reason:"terminal actor is already known; session introspection is an agent tool"},tool("stateengine_whoami","Identity","Read bound identity, session and grants. Copy returned IDs; do not invent IDs."),Session,false,Never,Read,Session,None,"se.principal",Principal,&["J2","J3","J4"]);
    #[cfg(feature = "import")]
    ImportNode => ImportNode, ImportReceipt, ("store.import_node",leaf(&["import"]),no_mcp("Explicit owner migration preserves the original Node history."),Owner,false,Never,Custody,Home,HostAutoStart,"se.import",Import,&["J2","J3","J4"]);
    ProjectInit => ProjectInit, InitOutput, ("project.init",leaf(&["init"]),no_mcp("Owner setup registers the managed workspace."),Owner,false,Never,Write,Home,None,"se.init",Init,&["J2"]);
    ProjectMove => ProjectMove, MoveOutput, ("project.move",leaf(&["project","move"]),no_mcp("Owner terminal operation: re-attach the project to a moved repository folder after verifying its recorded git identity."),Owner,false,Never,Write,Project,None,"se.project-move",ProjectMove,&["J3"]);
    DiagnosticBundle => DiagnosticBundle, DiagnosticBundleOutput, ("diagnostic.bundle",leaf(&["diagnostic-bundle"]),no_mcp("Home-wide owner diagnostics must not leak into a project session; ask the user to run the installed CLI and share the file."),Owner,false,Never,Read,Home,None,"se.diagnostic-bundle",Bundle,&["J5"]);
    DoctorInspect => DoctorInspect, Diagnosis, ("doctor.inspect",leaf(&["doctor"]),no_mcp("Owner installation diagnosis uses the installed CLI."),Owner,false,Never,Read,Home,None,"se.diagnosis",Diagnosis,&["J5"]);
    DoctorRepair => DoctorRepair, RepairOutput, ("doctor.repair",CliExposure::Leaf {path:&["doctor"],hidden:false,select:Selector::Flag("fix")},no_mcp("One-check repair requires an owner terminal."),Owner,false,Always,Write,Home,None,"se.repair",Repair,&["J5"]);
    ProjectStatus => ProjectStatus, StatusOutput, ("project.status",leaf(&["status"]),tool("stateengine_status","Project status","Read project setup, agents and runtime facts."),Either,false,Never,Read,ProjectOrAll,None,"se.status",Status,&["J1","J2"]);
    EventRead => EventRead, EventOutput, ("history.event_read",CliExposure::Leaf {path:&["history"],hidden:false,select:Selector::Flag("event")},tool("stateengine_event_read","Read a committed event","Read one committed project event and its provenance."),Either,false,Never,Read,Project,None,"se.event",Event,&["E3","J3","J4"]);
    HistoryList => HistoryList, HistoryPage, ("history.list",leaf(&["history"]),no_mcp("Sessions use event_read for exact public records; owner CLI history is read-only inspection."),Either,false,Never,Read,Project,None,"se.history-page",HistoryPage,&["J3"]);
    MessageSend => MessageSend, MessageOutput, ("message.send",leaf(&["msg","send"]),tool("stateengine_msg_send","Send a message","Send direct or floor mail; floor requires work.action/addressees. quiet suppresses notification, not unread state."),Either,false,Never,Write,Project,HostForWrites,"se.message-receipt",MessageReceipt,&["J4"]);
    MessageRead => MessageRead, MessageReadOutput, ("message.read",leaf(&["msg","read"]),tool("stateengine_msg_read","Read one complete message","Read a complete message and mark it read as recipient. msg_id aliases message_id."),Either,false,Never,Write,Project,HostForWrites,"se.message-read",MessagePage,&["J4"]);
    MessageAck => MessageAck, DispositionReceipt, ("message.ack",leaf(&["msg","ack"]),tool("stateengine_msg_ack","Acknowledge a message","Mark your message read without its body. msg_id aliases message_id."),Either,false,Never,Write,Project,HostForWrites,"se.disposition-receipt",MessageReceipt,&["J4"]);
    MessageDismiss => MessageDismiss, DispositionReceipt, ("message.dismiss",leaf(&["msg","dismiss"]),tool("stateengine_msg_dismiss","Dismiss a message","Dismiss your message without marking read. msg_id aliases message_id."),Either,false,Never,Write,Project,HostForWrites,"se.disposition-receipt",MessageReceipt,&["J4"]);
    MessageList => MessageList, MessagePage, ("message.list",leaf(&["msg","list"]),tool("stateengine_msg_list","List your messages","List authorized mail with completeness; never marks read. full returns bodies."),Either,false,Never,Read,Project,None,"se.message-page",MessagePage,&["J4"]);
    MessageInbox => MessageInbox, MessagePage, ("message.inbox",leaf(&["msg","inbox"]),no_mcp("Bound agents use stateengine_msg_list with its unread inbox view."),Either,false,Never,Read,Project,None,"se.message-page",MessagePage,&["J3","J4"]);
    WorkingStateGet => WorkingStateGet, WorkingStateOutput, ("working_state.get",leaf(&["working-state"]),tool("stateengine_working_state_get","Read working state","Read your note and revision."),Either,false,Never,Read,Session,None,"se.working-state",WorkingState,&["J3"]);
    WorkingStateSet => WorkingStateSet, WorkingStateReceipt, ("working_state.set",leaf(&["working-state","set"]),tool("stateengine_working_state_set","Replace working state","Replace your note; expect is its read revision, or absent for first write."),Either,false,Never,Write,Session,HostForWrites,"se.working-state-receipt",WorkingStateReceipt,&["J3"]);
    HookClaude => HookClaude, HookResult, ("hook.claude",CliExposure::Leaf {path:&["hook","claude"],hidden:true,select:Selector::Always},no_mcp("Provider hooks use authenticated native stdin and pinned-source capture."),Session,false,Never,Custody,Session,HostAutoStart,"se.hook-result",Hook,&["E3","J3"]);
    RuntimeUp => RuntimeUp, RuntimeStart, ("runtime.up",leaf(&["up"]),no_mcp("Runtime custody is an owner operation."),Owner,false,Never,Custody,Home,HostAutoStart,"se.runtime-start",RuntimeStart,&["J3"]);
    RuntimeDown => RuntimeDown, RuntimeStop, ("runtime.down",leaf(&["down"]),no_mcp("Runtime custody is an owner operation."),Owner,false,Never,Custody,Home,None,"se.runtime-stop",RuntimeStop,&["J3"]);
    Uninstall => Uninstall, UninstallOutput, ("installation.uninstall",leaf(&["uninstall"]),no_mcp("Installation removal uses the local owner CLI."),Owner,false,Always,Custody,Home,None,"se.uninstall",Uninstall,&["J5"]);
    AgentCreate => AgentCreate, AgentReceipt, ("agent.create",leaf(&["agent","add"]),tool("stateengine_agent_create","Create an agent","Save an agent/profile without launching. Requires your current create grant."),Either,false,Never,Write,Project,HostForWrites,"se.agent-receipt",AgentReceipt,&["E3","J2","J4"]);
    AgentRename => AgentRename, AgentReceipt, ("agent.rename",leaf(&["agent","rename"]),no_mcp("owner controls identity labels"),Owner,false,Never,Write,Project,HostForWrites,"se.agent-receipt",AgentReceipt,&["J2","J3","J4"]);
    Resume => Resume, ResumeOutput, ("continuity.resume",leaf(&["resume"]),tool("stateengine_resume","Restore your context","Restore your context; omitted detail names full reads. Does not acknowledge mail."),Either,false,Never,Read,Project,None,"se.resume",Resume,&["J3","J4"]);
    SessionContext => SessionContextRequest, SessionContextOutput, ("session.context",CliExposure::Leaf{path:&["session","context"],hidden:true,select:Selector::Always},no_mcp("Harness/SE Code context uses the verified bound session; model tools use stateengine_resume."),Session,false,Never,Read,Session,None,"secode.session-context",SessionContext,&["J2","J3"]);
    AgentList => AgentList, AgentPage, ("agent.list",leaf(&["agent","list"]),no_mcp("Owner overview; bound agents use status for their own saved identity."),Owner,false,Never,Read,Project,None,"se.agent-page",AgentPage,&["J2","J3"]);
    AgentLaunch => AgentLaunch, LaunchReply, ("agent.launch",leaf(&["launch"]),tool("stateengine_agent_launch","Launch an agent","Launch self or your controlled child; same-key retry for pending. force consents to stop existing jobs."),Either,false,Never,Custody,Project,HostAutoStart,"se.launch",Launch,&["J2","J3"]);
    AgentStop => AgentStop, StopResult, ("agent.stop",leaf(&["stop"]),tool("stateengine_agent_stop","Stop an agent","Stop self or your controlled child; returns original-conversation resume command."),Either,false,Never,Custody,ProjectOrAll,HostAutoStart,"se.stop",Stop,&["J3","J5"]);
    AgentWake => AgentWake, WakeResult, ("agent.wake",leaf(&["agent","wake"]),tool("stateengine_agent_wake","Wake an agent","Arm this running agent's pending mail delivery and report the committed offer; never launches a process."),Either,false,Never,Custody,Project,Host,"se.wake",Wake,&["J4"]);
    ProjectRemove => ProjectRemove, RemoveResult, ("project.remove",leaf(&["remove"]),no_mcp("Project removal requires the verified owner at a human terminal."),Owner,false,Always,Custody,ProjectOrAll,HostAutoStart,"se.remove",Remove,&["J5"]);
    AgentShow => AgentShow, AgentStatusOutput, ("agent.show",leaf(&["agent","show"]),no_mcp("This owner CLI read inspects saved agent metadata."),Owner,false,Never,Read,Project,None,"se.agent-status",AgentStatus,&["E3","J2"]);
    ConfigGet => ConfigGet, ConfigValueOutput, ("config.get",leaf(&["config","get"]),no_mcp("Saved agent settings are inspected by the owner CLI."),Owner,false,Never,Read,Project,None,"se.config-value",ConfigValue,&["E3"]);
    ConfigSet => ConfigSet, AgentConfigReceipt, ("config.set",leaf(&["config","set"]),no_mcp("Saved agent metadata changes are owner CLI operations."),Owner,false,ConfigKey,Write,Project,HostForWrites,"se.config-receipt",ConfigReceipt,&["E3"]);
    ConfigList => ConfigList, ConfigPageOutput, ("config.list",leaf(&["config","list"]),no_mcp("Configuration is owner administration."),Owner,false,Never,Read,Home,None,"se.config-page",ConfigPage,&["J2","J3","J4","J5"]);
}
impl AnyOp {
    pub fn is_remote(&self) -> bool {
        matches!(
            self,
            Self::RemotePrepareSend(_)
                | Self::RemoteList(_)
                | Self::RemoteWatch(_)
                | Self::RemoteSend(_)
                | Self::RemoteLaunch(_)
        )
    }
    pub fn is_client(&self) -> bool {
        self.is_remote() || matches!(self, Self::ClientWatch(_))
    }
    /// Shared per-operation/per-key classification for CLI and host admission.
    pub fn requires_human_terminal(&self) -> Result<bool> {
        if let Self::Uninstall(input) = self {
            return Ok(!input.yes);
        }
        if matches!(self, Self::AgentStop(input) if input.release) {
            return Ok(true);
        }
        match self.meta().human_only {
            HumanPolicy::Always => Ok(true),
            HumanPolicy::Never => Ok(false),
            HumanPolicy::ConfigKey => match self {
                Self::ConfigSet(input) => {
                    Ok(se_config::config_policy::key_metadata(&input.key)?.human_only)
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
            #[cfg(feature = "import")]
            Self::ImportNode(v) => Some(&v.idempotency_key),
            Self::RemoteSend(v) => Some(&v.request.idempotency_key),
            Self::RemoteLaunch(v) => Some(&v.request.idempotency_key),
            Self::MessageSend(v) => Some(&v.idempotency_key),
            Self::WorkingStateSet(v) => Some(&v.idempotency_key),
            Self::RuntimeUp(v) => Some(&v.idempotency_key),
            Self::RuntimeDown(v) => Some(&v.idempotency_key),
            Self::Uninstall(v) => Some(&v.idempotency_key),
            Self::AgentCreate(v) => Some(&v.idempotency_key),
            Self::AgentRename(v) => Some(&v.idempotency_key),
            Self::AgentLaunch(v) => Some(&v.idempotency_key),
            Self::AgentStop(v) => Some(&v.idempotency_key),
            Self::ProjectRemove(v) => Some(&v.idempotency_key),
            Self::ConfigSet(v) => Some(&v.idempotency_key),
            _ => None,
        }
    }
    pub fn resolve_stdin(
        &mut self,
        read: &mut dyn FnMut(String, &str, usize) -> Result<String>,
    ) -> Result<()> {
        match self {
            Self::RemoteSend(v) => {
                v.request.body = se_types::Body::new(read(
                    v.request.body.as_str().to_owned(),
                    "body",
                    se_types::MESSAGE_BODY_MAX_BYTES,
                )?)?;
            }
            Self::MessageSend(v) => {
                v.body = read(v.body.clone(), "body", se_types::MESSAGE_BODY_MAX_BYTES)?
            }
            Self::WorkingStateSet(v) => {
                v.text = read(v.text.clone(), "text", se_types::WORKING_STATE_MAX_BYTES)?
            }
            _ => (),
        }
        self.validate()
    }
}
impl AnyOutput {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::RemoteLaunch(v) => {
                if matches!(
                    v.value.outcome,
                    se_types::remote::RemoteLaunchOutcome::Pending { .. }
                ) {
                    2
                } else {
                    0
                }
            }
            Self::RemoteSend(v) => match v.value.receipt {
                se_types::Receipt::Committed { .. } | se_types::Receipt::Replayed { .. } => 0,
                se_types::Receipt::Refused { .. } => 1,
                se_types::Receipt::Pending { .. } => 2,
            },
            Self::RemoteList(v) if !v.value.agents.window().complete() => 2,
            Self::RemoteWatch(v) if !v.value.complete || v.value.reset_required => 2,
            // Native Claude framing has its own availability exit. Explicit
            // JSON callers must still observe a failed or unconfirmed capture.
            Self::HookClaude(v) => v.value.failure.as_ref().map_or_else(
                || v.value.captured.exit_code(),
                |failure| failure.class().exit_code(),
            ),
            Self::AtlasFind(v) => match &v.value.answer.data {
                se_types::Read::Present { value } => value.page.window().exit_code(false),
                other => other.exit_code(),
            },
            Self::AtlasRefs(v) => atlas::page_exit(&v.value.answer.data),
            Self::AtlasChanges(v) => atlas::page_exit(&v.value.answer.data),
            Self::AtlasImpact(v) => atlas::complete_exit(&v.value.answer.data, |v| v.complete),
            Self::AtlasOutline(v) => atlas::complete_exit(&v.value.answer.data, |v| v.complete),
            Self::DiagnosticBundle(v) if !v.value.complete => 2,
            Self::DoctorInspect(v) => v.value.exit_code(),
            Self::DoctorRepair(v) if !v.value.complete => 2,
            Self::Uninstall(v) if !v.value.complete => 2,
            #[cfg(feature = "import")]
            Self::ImportNode(v) if !v.value.complete => 2,
            Self::AgentStop(v) if !v.value.complete => 2,
            Self::AgentWake(v) => match &v.value.outcome {
                crate::ops::agent_wake::WakeOutcome::Offered => 0,
                crate::ops::agent_wake::WakeOutcome::Pending => 2,
                crate::ops::agent_wake::WakeOutcome::Refused
                | crate::ops::agent_wake::WakeOutcome::Delivered => 1,
            },
            Self::ProjectRemove(v) if !matches!(v.value.outcome.as_str(), "removed" | "absent") => {
                2
            }
            Self::RuntimeDown(v) if !v.value.complete => 2,
            Self::RuntimeUp(v) if v.value.state == "pending" => 2,
            Self::EventRead(v) => match &v.value {
                EventOutput::Present(_) => 0,
                EventOutput::Other(value) => value.exit_code(),
            },
            Self::WorkingStateGet(v) => v.value.value.exit_code(),
            Self::ConfigGet(v) => v.value.value.exit_code(),
            Self::ConfigList(v) => v.value.page.window().exit_code(false),
            Self::AgentShow(v) => v.value.agent.exit_code(),
            Self::Resume(v) => v.value.exit_code(),
            Self::SessionContext(v) if v.value.truncated || !v.value.failures.is_empty() => 2,
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
                    || equal(row.name, "meta.guide")
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

#[cfg(test)]
mod input_schema_tests {
    use super::{CATALOGUE, advertised_input_schema, input_schema, meta::mcp_tools};
    use serde_json::Value;

    #[test]
    fn every_op_input_schema_advertises_an_object() {
        for meta in CATALOGUE {
            let schema = input_schema(meta.name)
                .unwrap_or_else(|| panic!("{} has no input schema", meta.name));
            assert_eq!(
                schema.get("type"),
                Some(&Value::String("object".into())),
                "{} advertises a non-object input root",
                meta.name
            );
        }
    }

    #[test]
    fn whoami_discovery_advertises_object_arguments() {
        let tools = mcp_tools().unwrap_or_else(|error| panic!("mcp tool list: {error}"));
        let whoami = tools
            .iter()
            .find(|tool| tool.name == "stateengine_whoami")
            .unwrap_or_else(|| panic!("whoami tool registered"));
        assert_eq!(
            whoami.input_schema.get("type"),
            Some(&Value::String("object".into()))
        );
        let properties = whoami
            .input_schema
            .get("properties")
            .and_then(Value::as_object)
            .unwrap_or_else(|| panic!("whoami advertises properties"));
        assert!(properties.contains_key("agent_id"));
        assert!(properties.contains_key("project_id"));
    }

    #[test]
    fn unit_struct_schema_root_null_is_rewritten_to_object() {
        let schema = advertised_input_schema(serde_json::json!({
            "type": "null",
            "title": "IdentityWhoami"
        }));
        assert_eq!(
            schema,
            serde_json::json!({"type": "object", "title": "IdentityWhoami"})
        );
    }
}
