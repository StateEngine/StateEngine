//! The operation list for the executable wave-one surface. Later waves add their
//! production operations here; no placeholder handlers or phantom tools are exposed.
pub mod administration;
mod cli;
pub mod decision;
pub mod hook;
pub mod inputs;
pub mod installation;
pub mod message;
mod meta;
pub mod outputs;
pub mod receipt;
pub mod status;
pub use crate::commit::{MessageSend, WorkingStateSet};
use crate::registry::*;
pub use cli::{
    CliSelections, CommonArgs, cli_command, from_matches, from_matches_with_key, selected_meta,
};
pub use hook::{HookClaude, HookEvent, HookResult};
pub use inputs::*;
pub use meta::{
    McpTool, decode_operation, decode_tool, mcp_tools, metadata_output, schema_catalogue,
};
pub use outputs::*;
use schemars::JsonSchema;
use se_types::{API_VERSION, IdempotencyKey, Result};
use serde::{Serialize, Serializer};

#[derive(Clone, Debug, Serialize, serde::Deserialize, JsonSchema)]
pub struct Envelope<T> {
    schema: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostics: Option<OutputDiagnostics>,
    #[serde(flatten)]
    pub value: T,
}
impl<T> Envelope<T> {
    fn new(family: Family, value: T) -> Self {
        Self {
            schema: family.schema(),
            diagnostics: None,
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
        #[derive(Clone, Debug, JsonSchema)]
        #[serde(untagged)]
        pub enum AnyOutput { $( $variant(Box<Envelope<$output>>), )+ }
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
        impl AnyOutput {
            pub fn family(&self) -> Family { match self { $( Self::$variant(_)=><$input>::META.family, )+ } }
            pub fn human_kind(&self) -> HumanKind { match self { $( Self::$variant(_)=><$input>::META.human, )+ } }
            /// Called by the host with this request's store measurements. Direct
            /// output constructors leave diagnostics absent.
            pub fn with_write_timings(mut self, timings: ReceiptWriteTimings) -> Self {
                match &mut self { $( Self::$variant(value)=>value.diagnostics=Some(OutputDiagnostics { write_timings: timings }), )+ }
                self
            }
        }
        impl Serialize for AnyOutput {
            fn serialize<S:Serializer>(&self,serializer:S)->std::result::Result<S::Ok,S::Error> { match self { $( Self::$variant(value)=>value.serialize(serializer), )+ } }
        }
        impl<'de> serde::Deserialize<'de> for AnyOutput {
            fn deserialize<D:serde::Deserializer<'de>>(decoder:D)->std::result::Result<Self,D::Error> {
                let value=<serde_json::Value as serde::Deserialize>::deserialize(decoder)?;
                let family=value.get("schema").and_then(serde_json::Value::as_str).ok_or_else(||serde::de::Error::custom("missing output family schema"))?;
                $(if family==<$input>::META.family.schema() {
                    let envelope=serde_json::from_value::<Envelope<$output>>(value).map_err(serde::de::Error::custom)?;
                    if let Some(diagnostics)=&envelope.diagnostics {
                        diagnostics.write_timings.validate().map_err(serde::de::Error::custom)?;
                    }
                    return Ok(Self::$variant(Box::new(envelope)));
                })+
                Err(serde::de::Error::custom("unknown output family schema"))
            }
        }
        $(impl From<$output> for AnyOutput {
            fn from(value:$output)->Self { Self::$variant(Box::new(Envelope::new(<$input>::META.family,value))) }
        })+
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
    MessageSend => MessageSend, MessageOutput, ("message.send",leaf(&["msg","send"]),tool("stateengine_msg_send","Send a message","Commit a message to another project agent or owner; committed does not mean read."),Either,false,Never,Write,Project,HostForWrites,"se.message-receipt",MessageReceipt,&["J4"]);
    MessageList => MessageList, MessagePage, ("message.list",leaf(&["msg","list"]),tool("stateengine_msg_list","List your messages","List authorized messages with explicit completeness; listing never marks mail read."),Either,false,Never,Read,Project,None,"se.message-page",MessagePage,&["J4"]);
    WorkingStateGet => WorkingStateGet, WorkingStateOutput, ("working_state.get",leaf(&["working-state"]),tool("stateengine_working_state_get","Read working state","Read your saved note and entity revision."),Either,false,Never,Read,Session,None,"se.working-state",WorkingState,&["J3"]);
    WorkingStateSet => WorkingStateSet, WorkingStateReceipt, ("working_state.set",leaf(&["working-state","set"]),tool("stateengine_working_state_set","Replace working state","Replace your note with the revision you read or absent for the first write."),Either,false,Never,Write,Session,HostForWrites,"se.working-state-receipt",WorkingStateReceipt,&["J3"]);
    HookClaude => HookClaude, HookResult, ("hook.claude",CliExposure::Leaf {path:&["hook","claude"],hidden:true,select:Selector::Always},no_mcp("Provider hooks use authenticated native stdin and pinned-source capture."),Session,false,Never,Custody,Session,HostAutoStart,"se.hook-result",Hook,&["E3","J3"]);
    RuntimeUp => RuntimeUp, RuntimeStart, ("runtime.up",leaf(&["up"]),no_mcp("Runtime custody is an owner operation."),Owner,false,Never,Custody,Home,HostAutoStart,"se.runtime-start",RuntimeStart,&["J3"]);
    RuntimeDown => RuntimeDown, RuntimeStop, ("runtime.down",leaf(&["down"]),no_mcp("Runtime custody is an owner operation."),Owner,false,Never,Custody,Home,None,"se.runtime-stop",RuntimeStop,&["J3"]);
    Uninstall => Uninstall, UninstallOutput, ("installation.uninstall",leaf(&["uninstall"]),no_mcp("Installation removal requires the owner at a human terminal."),Owner,false,Always,Custody,Home,None,"se.uninstall",Uninstall,&["J5"]);
}
impl AnyOp {
    pub fn idempotency_key(&self) -> Option<&IdempotencyKey> {
        match self {
            Self::ProjectInit(v) => Some(&v.idempotency_key),
            Self::MessageSend(v) => Some(&v.idempotency_key),
            Self::WorkingStateSet(v) => Some(&v.idempotency_key),
            Self::RuntimeUp(v) => Some(&v.idempotency_key),
            Self::RuntimeDown(v) => Some(&v.idempotency_key),
            Self::Uninstall(v) => Some(&v.idempotency_key),
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
            _ => (),
        }
        self.validate()
    }
}
impl AnyOutput {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Uninstall(v) if !v.value.complete => 2,
            Self::RuntimeDown(v) if !v.value.complete => 2,
            Self::RuntimeUp(v) if v.value.state == "pending" => 2,
            Self::WorkingStateGet(v) => v.value.value.exit_code(),
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
                }) || (v.value.view.op == "inbox"
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
