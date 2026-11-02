// SPDX-License-Identifier: MIT OR Apache-2.0

pub type Result<T> = std::result::Result<T, ApiError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApiFailure {
    NotIncluded,
    Usage,
    Refused,
    Unauthorized,
    Unknown,
    Unreadable,
    Conflict,
    Incomplete,
    Unavailable,
    Cancelled,
    EnginePanicked,
    GenerationPoisoned,
    Internal,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApiCommand {
    Tool {
        name: String,
        args: serde_json::Value,
    },
    Manual,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiRemedy {
    pub text: String,
    pub command: Option<ApiCommand>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApiRetry {
    Never,
    AfterMillis(u64),
    AfterRefresh,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApiError {
    pub kind: ApiFailure,
    pub code: String,
    pub message: String,
    pub remedy: ApiRemedy,
    pub retry: ApiRetry,
}
