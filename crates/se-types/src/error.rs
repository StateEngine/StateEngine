use crate::{
    AgentId, Cursor, DecisionId, EventId, Generation, LaunchId, MessageId, ObservationId,
    ProjectId, SessionId, UnixMicros,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{error::Error, fmt, time::Duration};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Usage,
    Refused,
    Unauthorized,
    Unknown,
    Unreadable,
    Conflict,
    Incomplete,
    Unavailable,
    Internal,
    Cancelled,
}
impl Class {
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::Usage => 64,
            Self::Unknown => 4,
            Self::Unreadable => 3,
            Self::Incomplete => 2,
            Self::Refused
            | Self::Unauthorized
            | Self::Conflict
            | Self::Unavailable
            | Self::Internal
            | Self::Cancelled => 1,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProjectChoice {
    pub name: String,
    pub id: ProjectId,
    pub root: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ImportFamilyIssue {
    pub name: String,
    pub rejected: u64,
    pub unreadable: u64,
}

/// Original write identity retained by a bounded admission refusal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct WriteRetryIdentity {
    pub operation: String,
    pub key: Option<String>,
    pub natural_events: Vec<EventId>,
}

macro_rules! codes {
    ($($variant:ident => ($wire:literal,$class:ident) { $($field:ident:$ty:ty),* $(,)? } => $message:literal,$remedy:literal;)+) => {
        $(const _: [();1] = [();($wire.len()>0 && $message.len()>0 && $remedy.len()>1) as usize];)+
        #[non_exhaustive]
        #[derive(Clone,Copy,Debug,Eq,PartialEq,Hash,Serialize,Deserialize,JsonSchema)]
        pub enum Code{$(#[serde(rename=$wire)] $variant,)+}
        pub mod details{use super::*;$(
            #[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize,JsonSchema)]
            pub struct $variant{$(pub $field:$ty,)*}
        )+}
        #[derive(Clone,Debug,Eq,PartialEq,Serialize,Deserialize,JsonSchema)]
        #[serde(tag="code",content="detail")]
        pub enum Detail{$(#[serde(rename=$wire)] $variant(details::$variant),)+}
        impl Code{
            pub const fn as_str(self)->&'static str{match self{$(Self::$variant=>$wire,)+}}
            pub const fn class(self)->Class{match self{$(Self::$variant=>Class::$class,)+}}
            pub fn message(self,detail:&Detail)->crate::Result<String>{
                if self!=detail.code(){return Err(SeError::invalid("detail","detail matching the error code"));}
                Ok(detail.message())
            }
            pub fn remedy(self,detail:&Detail,cx:&RenderCx<'_>)->crate::Result<Remedy>{
                if self!=detail.code(){return Err(SeError::invalid("detail","detail matching the error code"));}
                let text=match self{$(Self::$variant=>render($remedy,detail,Some(cx)),)+};
                let command=match cx.commands{Some(commands)=>commands.for_error(&ErrorBody::new(detail.clone()))?,None=>None};
                Ok(Remedy{text,command})
            }
        }
        impl Detail{
            pub const fn code(&self)->Code{match self{$(Self::$variant(_)=>Code::$variant,)+}}
            pub fn message(&self)->String{match self{$(Self::$variant(_)=>render($message,self,None),)+}}
            fn message_in(&self,cx:&RenderCx<'_>)->String{match self{$(Self::$variant(_)=>render($message,self,Some(cx)),)+}}
            fn fields(&self)->Vec<(&'static str,String,Option<usize>)>{match self{$(Self::$variant(value)=>vec![$((stringify!($field),value.$field.human(),value.$field.count()),)*],)+}}
        }
    };
}
include!("error/catalog.rs");

trait HumanValue {
    fn human(&self) -> String;
    fn count(&self) -> Option<usize> {
        None
    }
}
macro_rules! display_values {
    ($($ty:ty),+ $(,)?) => {$(impl HumanValue for $ty {fn human(&self)->String {self.to_string()}})+};
}
display_values!(
    str,
    String,
    Cursor,
    u16,
    u32,
    u64,
    i32,
    AgentId,
    DecisionId,
    EventId,
    LaunchId,
    MessageId,
    ObservationId,
    ProjectId,
    SessionId,
    UnixMicros
);
impl HumanValue for Generation {
    fn human(&self) -> String {
        self.get().to_string()
    }
}
impl HumanValue for WriteRetryIdentity {
    fn human(&self) -> String {
        format!(
            "{}; key {}; natural events {}",
            self.operation,
            self.key.human(),
            self.natural_events.human()
        )
    }
}
impl<T: HumanValue + ?Sized> HumanValue for Box<T> {
    fn human(&self) -> String {
        self.as_ref().human()
    }
    fn count(&self) -> Option<usize> {
        self.as_ref().count()
    }
}
impl<T: HumanValue> HumanValue for Option<T> {
    fn human(&self) -> String {
        self.as_ref()
            .map(HumanValue::human)
            .unwrap_or_else(|| "unknown".into())
    }
}
impl<T: HumanValue> HumanValue for [T] {
    fn human(&self) -> String {
        self.iter()
            .map(HumanValue::human)
            .collect::<Vec<_>>()
            .join(", ")
    }
    fn count(&self) -> Option<usize> {
        Some(self.len())
    }
}
impl<T: HumanValue> HumanValue for Vec<T> {
    fn human(&self) -> String {
        self.as_slice().human()
    }
    fn count(&self) -> Option<usize> {
        Some(self.len())
    }
}
impl HumanValue for ProjectChoice {
    fn human(&self) -> String {
        format!("{} ({}, {})", self.name, self.id, self.root)
    }
}
impl HumanValue for ImportFamilyIssue {
    fn human(&self) -> String {
        format!(
            "{}: {} rejected, {} unreadable",
            self.name, self.rejected, self.unreadable
        )
    }
}
fn render(template: &str, detail: &Detail, cx: Option<&RenderCx<'_>>) -> String {
    let fields = detail.fields();
    let mut output = String::new();
    let mut rest = template;
    // Single pass: braces inside a detail string are data, never another template.
    while let Some(start) = rest.find('{') {
        output.push_str(&rest[..start]);
        let token = &rest[start..];
        let Some(end) = token.find('}') else {
            output.push_str(token);
            return output;
        };
        let name = &token[1..end];
        if let Some(field) = name.strip_suffix(".len") {
            match fields
                .iter()
                .find(|(key, _, _)| *key == field)
                .and_then(|(_, _, count)| *count)
            {
                Some(count) => output.push_str(&count.to_string()),
                None => output.push_str(&token[..=end]),
            }
        } else if let Some((_, value, _)) = fields.iter().find(|(key, _, _)| *key == name) {
            output.push_str(value);
        } else {
            match name {
                "project" => output.push_str(
                    &cx.and_then(|cx| cx.project)
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "PROJECT".into()),
                ),
                "agent" => output.push_str(
                    &cx.and_then(|cx| cx.agent)
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "AGENT".into()),
                ),
                "root" => output.push_str("DIR"),
                _ => output.push_str(&token[..=end]),
            }
        }
        rest = &token[end + 1..];
    }
    output.push_str(rest);
    output
}

mod duration_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;
    pub fn serialize<S: Serializer>(
        value: &Duration,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if !value.subsec_nanos().is_multiple_of(1_000_000) {
            return Err(serde::ser::Error::custom(
                "retry duration must be whole milliseconds",
            ));
        }
        let millis = u64::try_from(value.as_millis()).map_err(serde::ser::Error::custom)?;
        serializer.serialize_u64(millis)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Duration, D::Error> {
        u64::deserialize(deserializer).map(Duration::from_millis)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Retry {
    #[default]
    Never,
    AfterReread,
    After(
        #[serde(with = "duration_millis")]
        #[schemars(with = "u64")]
        Duration,
    ),
    WhenRuntimeReady,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ErrorBody {
    #[serde(flatten)]
    detail: Detail,
    #[serde(default)]
    retry: Retry,
}
impl ErrorBody {
    pub fn new(detail: Detail) -> Self {
        let retry = match &detail {
            Detail::SessionNotActive(_) => Retry::AfterReread,
            _ => Retry::Never,
        };
        Self {
            detail,
            retry,
        }
    }
    pub fn with_retry(mut self, retry: Retry) -> Self {
        self.retry = retry;
        self
    }
    pub fn code(&self) -> Code {
        self.detail.code()
    }
    pub fn class(&self) -> Class {
        self.code().class()
    }
    pub fn detail(&self) -> &Detail {
        &self.detail
    }
    pub fn retry(&self) -> &Retry {
        &self.retry
    }
    pub fn message(&self) -> String {
        self.detail.message()
    }
    pub fn remedy(&self, cx: &RenderCx<'_>) -> crate::Result<Remedy> {
        self.code().remedy(&self.detail, cx)
    }
}
impl fmt::Display for ErrorBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code().as_str(), self.message())
    }
}
#[derive(Debug)]
pub struct SeError {
    pub body: ErrorBody,
    pub cause: Option<Box<dyn Error + Send + Sync>>,
}
impl SeError {
    pub fn new(detail: Detail) -> Self {
        Self {
            body: ErrorBody::new(detail),
            cause: None,
        }
    }
    pub fn invalid(field: &str, expected: &str) -> Self {
        Self::new(Detail::UsageInvalidValue(details::UsageInvalidValue {
            argument: field.into(),
            got: "[redacted]".into(),
            expected: expected.into(),
        }))
    }
    pub fn too_large(field: &str, limit: usize, got: usize) -> Self {
        Self::new(Detail::InputTooLarge(details::InputTooLarge {
            field: field.into(),
            limit_bytes: limit as u64,
            got_bytes: got as u64,
        }))
    }
    pub fn with_cause(mut self, cause: impl Error + Send + Sync + 'static) -> Self {
        self.cause = Some(Box::new(cause));
        self
    }
    pub fn code(&self) -> Code {
        self.body.code()
    }
    pub fn class(&self) -> Class {
        self.body.class()
    }
    pub fn into_body(self) -> ErrorBody {
        self.body
    }
}
impl From<ErrorBody> for SeError {
    fn from(body: ErrorBody) -> Self {
        Self { body, cause: None }
    }
}
impl fmt::Display for SeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.body.fmt(f)
    }
}
impl Error for SeError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.cause
            .as_ref()
            .map(|cause| &**cause as &(dyn Error + 'static))
    }
}

/// Only generated typed operation inputs implement this; no raw argv constructor.
pub trait OperationCommand {
    fn cli_argv(&self) -> Vec<String>;
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(transparent)]
#[schemars(with = "Vec<String>")]
pub struct Argv(Vec<String>);
impl Argv {
    pub fn from_op(operation: &impl OperationCommand) -> crate::Result<Self> {
        Self::validate(operation.cli_argv())
    }
    fn validate(args: Vec<String>) -> crate::Result<Self> {
        if args.is_empty()
            || args.len() > 256
            || args.iter().any(|a| a.contains('\0') || a.len() > 32768)
        {
            return Err(SeError::invalid(
                "remedy argv",
                "1..256 bounded literal arguments without NUL",
            ));
        }
        Ok(Self(args))
    }
    pub fn as_slice(&self) -> &[String] {
        &self.0
    }
}
impl<'de> Deserialize<'de> for Argv {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let args = Vec::<String>::deserialize(deserializer)?;
        Self::validate(args).map_err(serde::de::Error::custom)
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Cmd {
    Se { argv: Argv },
    Tool { name: String, args: Value },
    Manual,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Remedy {
    pub text: String,
    pub command: Option<Cmd>,
}
pub trait RemedyCommands {
    /// Resolve to the canonical registry input, then use Argv::from_op.
    fn for_error(&self, error: &ErrorBody) -> crate::Result<Option<Cmd>>;
}
#[derive(Default)]
pub struct RenderCx<'a> {
    pub project: Option<&'a ProjectId>,
    pub agent: Option<&'a AgentId>,
    pub commands: Option<&'a dyn RemedyCommands>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(try_from = "ErrorEnvelopeWire", into = "ErrorEnvelopeWire")]
pub struct ErrorEnvelope {
    body: ErrorBody,
    message: String,
    remedy: Remedy,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
struct ErrorEnvelopeWire {
    schema: String,
    #[serde(flatten)]
    body: ErrorBody,
    class: Class,
    exit: u8,
    message: String,
    remedy: Remedy,
}
impl ErrorEnvelope {
    pub fn new(body: ErrorBody, cx: &RenderCx<'_>) -> crate::Result<Self> {
        let message = body.detail.message_in(cx);
        let remedy = body.remedy(cx)?;
        Ok(Self {
            body,
            message,
            remedy,
        })
    }
    pub fn body(&self) -> &ErrorBody {
        &self.body
    }
}
impl From<ErrorEnvelope> for ErrorEnvelopeWire {
    fn from(value: ErrorEnvelope) -> Self {
        Self {
            schema: "se.error/v1".into(),
            class: value.body.class(),
            exit: value.body.class().exit_code(),
            body: value.body,
            message: value.message,
            remedy: value.remedy,
        }
    }
}
impl TryFrom<ErrorEnvelopeWire> for ErrorEnvelope {
    type Error = SeError;
    fn try_from(value: ErrorEnvelopeWire) -> crate::Result<Self> {
        if value.schema != "se.error/v1"
            || value.class != value.body.class()
            || value.exit != value.body.class().exit_code()
            || value.message.is_empty()
            || value.remedy.text.is_empty()
        {
            return Err(SeError::invalid(
                "error envelope",
                "consistent se.error/v1 code, class, exit and message",
            ));
        }
        Ok(Self {
            body: value.body,
            message: value.message,
            remedy: value.remedy,
        })
    }
}
