//! Both renderings describe the same immutable plan before any native effect.
use se_core::{
    ops::doctor::{PermissionProtection, RepairPlan},
    scope,
};
use se_types::Result;
pub(super) fn emit(
    plan: &RepairPlan,
    json_output: bool,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<()> {
    let (id, target, effect) = match plan {
        RepairPlan::TightenPermissions(plan) => {
            let before = match &plan.expected_before.protection {
                PermissionProtection::Unix { mode, .. } => format!("Unix mode {mode:04o}"),
                PermissionProtection::Macos { mode, .. } => format!("macOS mode {mode:04o} and extended ACL (clear all entries on repair)"),
                PermissionProtection::Windows { .. } => "the pinned Windows DACL".into(),
            };
            (&plan.check_id, &plan.target,
                format!("tighten {before} to exact owner-only protection; preserve the same owner, native object, contents and descendants"))
        },
        RepairPlan::RetainEndpoint(plan) => (
            &plan.check_id,
            &plan.target,
            format!("retain {} exact bytes at {} and make the original absent under the exclusive runtime lease; signal no processes", plan.expected_before.bytes, plan.expected_after.retained),
        ),
        RepairPlan::RestoreRecordedPath(plan) => (
            &plan.check_id,
            &plan.target,
            "restore exactly one recorded PATH entry after comparing the complete original value; preserve user edits".into(),
        ),
    };
    let mut write = || -> std::io::Result<()> {
        diagnostic(&format!("Plan: repair {id} only at {target}; {effect}."))?;
        if json_output {
            diagnostic(&serde_json::to_string(plan).map_err(std::io::Error::other)?)?;
        }
        Ok(())
    };
    write().map_err(|error| {
        scope::unreadable("doctor plan output", &error.to_string()).with_cause(error)
    })
}
