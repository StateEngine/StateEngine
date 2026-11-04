//! Caller assertions may agree with authenticated custody, never select it.
use super::*;
const FIELDS: [(&str, bool); 5] = [
    ("agent_id", false),
    ("agentId", false),
    ("project_id", true),
    ("projectId", true),
    ("project", true),
];

pub(super) async fn bound(
    backend: &mut impl McpBackend,
    capability: Arc<Secret>,
    mut arguments: Value,
) -> Result<Value> {
    if !FIELDS
        .iter()
        .any(|(field, _)| arguments.get(field).is_some())
    {
        return Ok(arguments);
    }
    let principal = backend.bound_principal(capability).await?;
    for (field, project) in FIELDS {
        let Some(requested) = arguments.get(field) else {
            continue;
        };
        let bound = if project {
            principal.project.as_str()
        } else {
            principal.agent.as_str()
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
        for (field, _) in FIELDS {
            object.remove(field);
        }
    }
    Ok(arguments)
}
