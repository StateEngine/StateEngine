//! Typed, reviewable expectations printed before one selected repair effect.
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "effect", rename_all = "kebab-case")]
pub enum RepairPlan {
    TightenPermissions(PermissionRepairPlan),
    RetainEndpoint(EndpointRetentionPlan),
    RestoreRecordedPath(PathRepairPlan),
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PermissionRepairPlan {
    pub check_id: String,
    pub target: String,
    pub expected_before: PermissionBefore,
    pub expected_after: PermissionAfter,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PermissionBefore {
    pub native_object: String,
    pub owner: String,
    pub protection: PermissionProtection,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "platform", rename_all = "kebab-case")]
pub enum PermissionProtection {
    Unix { mode: u32, group: u32 },
    Macos { mode: u32, group: u32, acl: String },
    Windows { sddl: String, control: u16 },
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub struct PermissionAfter {
    pub same_native_object: bool,
    pub same_owner: bool,
    pub owner_only: bool,
    pub retain_existing_owner_execute: bool,
    pub contents_unchanged: bool,
    pub descendants_unchanged: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EndpointRetentionPlan {
    pub check_id: String,
    pub target: String,
    pub expected_before: EndpointBefore,
    pub expected_after: EndpointAfter,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EndpointBefore {
    pub sha256: String,
    pub bytes: u64,
    pub exclusive_runtime_lease_required: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct EndpointAfter {
    pub original_absent: bool,
    pub retained: String,
    pub sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PathRepairPlan {
    pub check_id: String,
    pub target: String,
    pub expected_before: PathBefore,
    pub expected_after: PathAfter,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PathBefore {
    pub complete_value_sha256: Option<String>,
    pub recorded_entry_absent: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct PathAfter {
    pub recorded_entry_sha256: String,
    pub exact_entry_count: u32,
    pub existing_value_preserved: bool,
}
