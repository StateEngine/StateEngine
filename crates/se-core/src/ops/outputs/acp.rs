//! Current protocol observation; none of these values is an execution sandbox.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AcpRuntimeView {
    pub activity: String,
    pub mode: Option<String>,
    pub last_permission_refusal: Option<String>,
    pub provisional_reply: Option<AcpReplyPreview>,
    pub failure: Option<se_types::ErrorBody>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct AcpReplyPreview {
    pub text: String,
    pub total_bytes: u64,
    pub omitted_bytes: u64,
}
