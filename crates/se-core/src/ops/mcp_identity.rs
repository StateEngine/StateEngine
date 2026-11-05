//! Explicit MCP identity/project field roles, shared by admission and discovery.
use se_types::{Result, SeError};
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum IdentityRole {
    CallerAgent,
    CallerProject,
    Target,
}
const CALLER_DESCRIPTION: &str = "Caller assertion; optional; must match the bound identity";
type FieldRole = (&'static str, IdentityRole, &'static str);
pub const CALLER_FIELDS: &[FieldRole] = &[
    ("agent_id", IdentityRole::CallerAgent, CALLER_DESCRIPTION),
    ("agentId", IdentityRole::CallerAgent, CALLER_DESCRIPTION),
    (
        "project_id",
        IdentityRole::CallerProject,
        CALLER_DESCRIPTION,
    ),
    ("projectId", IdentityRole::CallerProject, CALLER_DESCRIPTION),
    ("project", IdentityRole::CallerProject, CALLER_DESCRIPTION),
];
const fn agent_target(description: &'static str) -> [FieldRole; 6] {
    [
        CALLER_FIELDS[0],
        CALLER_FIELDS[1],
        CALLER_FIELDS[2],
        CALLER_FIELDS[3],
        CALLER_FIELDS[4],
        ("target_agent_id", IdentityRole::Target, description),
    ]
}
const LAUNCH_FIELDS: &[FieldRole] = &agent_target("The seat to launch.");
const STOP_FIELDS: &[FieldRole] = &agent_target("The seat to stop.");
pub const MCP_IDENTITY_ARGUMENT_ROLES: &[(&str, &[FieldRole])] = &[
    ("stateengine_status", CALLER_FIELDS),
    ("stateengine_event_read", CALLER_FIELDS),
    ("stateengine_msg_send", CALLER_FIELDS),
    ("stateengine_msg_read", CALLER_FIELDS),
    ("stateengine_msg_ack", CALLER_FIELDS),
    ("stateengine_msg_dismiss", CALLER_FIELDS),
    ("stateengine_msg_list", CALLER_FIELDS),
    ("stateengine_working_state_get", CALLER_FIELDS),
    ("stateengine_working_state_set", CALLER_FIELDS),
    ("stateengine_agent_create", CALLER_FIELDS),
    ("stateengine_resume", CALLER_FIELDS),
    ("stateengine_agent_launch", LAUNCH_FIELDS),
    ("stateengine_agent_stop", STOP_FIELDS),
    ("stateengine_decision_list", CALLER_FIELDS),
    ("stateengine_decision_propose", CALLER_FIELDS),
];
pub fn fields(tool: &str) -> Result<&'static [FieldRole]> {
    MCP_IDENTITY_ARGUMENT_ROLES.iter().find_map(|(name, fields)| (*name == tool).then_some(*fields))
        .ok_or_else(|| SeError::invalid("MCP_IDENTITY_ARGUMENT_ROLES", &format!("an explicit caller/target field table for {tool}; no identity semantics are inferred")))
}
pub(super) fn describe(tool: &str, schema: &mut serde_json::Value) -> Result<()> {
    // Empty operation DTOs omit properties entirely; caller assertions still
    // need ordinary optional properties in their public MCP object schema.
    if schema.get("properties").is_none() {
        schema["properties"] = serde_json::json!({});
    }
    for (field, role, description) in fields(tool)? {
        if let Some(properties) = schema
            .get_mut("properties")
            .and_then(serde_json::Value::as_object_mut)
        {
            if *role == IdentityRole::Target {
                if let Some(property) = properties.get_mut(*field) {
                    property["description"] = serde_json::json!(description);
                }
            } else {
                if !["agent_id", "project_id"].contains(field) && !properties.contains_key(*field) {
                    continue;
                }
                properties.insert(
                    (*field).into(),
                    serde_json::json!({
                        "type": "string", "description": description
                    }),
                );
            }
        }
        if *role != IdentityRole::Target
            && let Some(required) = schema
                .get_mut("required")
                .and_then(serde_json::Value::as_array_mut)
        {
            required.retain(|name| name.as_str() != Some(field));
        }
    }
    Ok(())
}
