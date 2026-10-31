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
    }
}
output_types! {
MetaVersion => MetaVersion, VersionOutput;
MetaHelp => MetaHelp, HelpOutput;
MetaSchema => MetaSchema, SchemaCatalogue;
ProjectInit => ProjectInit, InitOutput;
ProjectStatus => ProjectStatus, StatusOutput;
MessageSend => MessageSend, MessageOutput;
MessageList => MessageList, MessagePage;
WorkingStateGet => WorkingStateGet, WorkingStateOutput;
WorkingStateSet => WorkingStateSet, WorkingStateReceipt;
HookClaude => HookClaude, HookResult;
RuntimeUp => RuntimeUp, RuntimeStart;
RuntimeDown => RuntimeDown, RuntimeStop;
Uninstall => Uninstall, UninstallOutput;
AgentCreate => AgentCreate, AgentReceipt;
AgentShow => AgentShow, AgentStatusOutput;
ConfigGet => ConfigGet, ConfigValueOutput;
ConfigSet => ConfigSet, AgentConfigReceipt;
Decision => DecisionPropose, DecisionReceipt;
}
