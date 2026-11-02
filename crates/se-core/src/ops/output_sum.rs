//! One variant per wire family; several operations share a receipt type.
//! Families and human kinds still come from the operation catalogue metadata.
use super::*;
use serde::{Serialize, Serializer};
macro_rules! output_types {
    ($( $variant:ident => $input:ty, $output:ty; )+) => {
        #[derive(Clone, Debug, JsonSchema)]
        #[serde(untagged)]
        pub enum AnyOutput { $( $variant(Box<Envelope<$output>>), )+ }
        impl AnyOutput {
            pub fn family(&self) -> Family { match self { $( Self::$variant(_)=><$input>::META.family, )+ } }
            pub fn maintenance_pending(&self) -> bool { match self { $( Self::$variant(value)=>value.maintenance_pending, )+ } }
            pub fn with_maintenance_pending(mut self, pending: bool) -> Self {
                match &mut self { $( Self::$variant(value)=>value.maintenance_pending=pending, )+ }
                self
            }
            pub fn human_kind(&self) -> HumanKind { match self { $( Self::$variant(_)=><$input>::META.human, )+ } }
            /// Called by the host with this request's store measurements. Direct
            /// output constructors leave diagnostics absent.
            pub fn with_write_timings(mut self, timings: ReceiptWriteTimings) -> Self {
                match &mut self { $( Self::$variant(value)=>value.diagnostics=Some(OutputDiagnostics { write_timings: timings, capture_commits: Vec::new() }), )+ }
                self
            }
        }
        impl AnyOutput {
            pub fn with_capture_commits(mut self, commits: Vec<CaptureCommitDiagnostics>) -> se_types::Result<Self> {
                if commits.len() > 128 {
                    return Err(se_types::SeError::invalid("capture diagnostics", "at most 128 commits per signal"));
                }
                if !commits.is_empty() {
                    let Self::HookClaude(value) = &mut self else {
                        return Err(se_types::SeError::invalid("capture diagnostics", "the hook output family only"));
                    };
                    for commit in &commits { commit.write_timings.validate()?; }
                    let diagnostics = value.diagnostics.as_mut().ok_or_else(||
                        se_types::SeError::invalid("capture diagnostics", "measured write diagnostics"))?;
                    diagnostics.capture_commits = commits;
                }
                Ok(self)
            }
        }
        impl Serialize for AnyOutput {
            fn serialize<S:Serializer>(&self,serializer:S)->std::result::Result<S::Ok,S::Error> { match self { $( Self::$variant(value)=>value.serialize(serializer), )+ } }
        }
        impl<'de> serde::Deserialize<'de> for AnyOutput {
            fn deserialize<D:serde::Deserializer<'de>>(decoder:D)->std::result::Result<Self,D::Error> {
                let value=<serde_json::Value as serde::Deserialize>::deserialize(decoder)?;
                let family=value.get("schema").and_then(serde_json::Value::as_str).ok_or_else(||serde::de::Error::custom("missing output family schema"))?.to_owned();
                $(if family==<$input>::META.family.schema() {
                    let envelope=serde_json::from_value::<Envelope<$output>>(value).map_err(serde::de::Error::custom)?;
                    if let Some(diagnostics)=&envelope.diagnostics {
                        diagnostics.write_timings.validate().map_err(serde::de::Error::custom)?;
                        if !diagnostics.capture_commits.is_empty() && family != "se.hook-result/v1" {
                            return Err(serde::de::Error::custom("capture diagnostics require the hook output family"));
                        }
                        if diagnostics.capture_commits.len() > 128 {
                            return Err(serde::de::Error::custom("capture diagnostics exceed the per-signal bound"));
                        }
                        for commit in &diagnostics.capture_commits {
                            commit.write_timings.validate().map_err(serde::de::Error::custom)?;
                        }
                    }
                    return Ok(Self::$variant(Box::new(envelope)));
                })+
                Err(serde::de::Error::custom("unknown output family schema"))
            }
        }
        $(impl From<$output> for AnyOutput {
            fn from(value:$output)->Self { Self::$variant(Box::new(Envelope::new(<$input>::META.family,value))) }
        })+
    }
}
output_types! {
Resume => Resume, ResumeOutput;
SessionContext => SessionContextRequest, SessionContextOutput;
MetaVersion => MetaVersion, VersionOutput;
MetaHelp => MetaHelp, HelpOutput;
MetaSchema => MetaSchema, SchemaCatalogue;
ProjectInit => ProjectInit, InitOutput;
ProjectStatus => ProjectStatus, StatusOutput;
EventRead => EventRead, EventOutput;
HistoryList => HistoryList, HistoryPage;
MessageSend => MessageSend, MessageOutput;
MessageList => MessageList, MessagePage;
WorkingStateGet => WorkingStateGet, WorkingStateOutput;
WorkingStateSet => WorkingStateSet, WorkingStateReceipt;
HookClaude => HookClaude, HookResult;
RuntimeUp => RuntimeUp, RuntimeStart;
RuntimeDown => RuntimeDown, RuntimeStop;
Uninstall => Uninstall, UninstallOutput;
AgentCreate => AgentCreate, AgentReceipt;
AgentLaunch => AgentLaunch, LaunchResult;
AgentStop => AgentStop, StopResult;
ProjectRemove => ProjectRemove, RemoveResult;
AgentShow => AgentShow, AgentStatusOutput;
AgentList => AgentList, AgentPage;
ConfigGet => ConfigGet, ConfigValueOutput;
ConfigSet => ConfigSet, AgentConfigReceipt;
DecisionShow => DecisionShow, DecisionOutput;
Decision => DecisionPropose, DecisionReceipt;
}
