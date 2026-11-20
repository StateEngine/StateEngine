//! Caller assertions may agree with authenticated custody, never select it.
use super::*;
use se_core::ops::mcp_identity::{self, IdentityRole};

pub(super) async fn bound(
    backend: &mut impl McpBackend,
    capability: Arc<Secret>,
    tool: &str,
    mut arguments: Value,
) -> Result<Value> {
    if !mcp_identity::CALLER_FIELDS
        .iter()
        .any(|(field, _, _)| arguments.get(field).is_some())
    {
        return Ok(arguments);
    }
    let fields = mcp_identity::fields(tool)?;
    let principal = backend.bound_principal(capability).await?;
    for &(field, role, _) in fields {
        let Some(requested) = arguments.get(field) else {
            continue;
        };
        if role == IdentityRole::Target {
            continue;
        }
        let bound = if role == IdentityRole::CallerProject {
            principal.project.as_str()
        } else {
            principal
                .agent
                .as_ref()
                .ok_or_else(|| {
                    SeError::new(se_types::Detail::CapabilityInvalid(
                        se_types::details::CapabilityInvalid {
                            subject: "guest connection".into(),
                            reason: "the caller has no agent identity".into(),
                            next_step: "Launch an agent through `se launch`.".into(),
                        },
                    ))
                })?
                .as_str()
        };
        if requested.as_str() != Some(bound) {
            return Err(SeError::invalid(
                "MCP caller assertion",
                &format!(
                    "{field}: bound value {bound:?}, requested {requested}; omit the field or use the exact bound value"
                ),
            ));
        }
    }
    if let Some(object) = arguments.as_object_mut() {
        for &(field, role, _) in fields {
            if role != IdentityRole::Target {
                object.remove(field);
            }
        }
    }
    Ok(arguments)
}
