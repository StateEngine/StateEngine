//! Explicit MCP identity/project field roles, shared by admission and discovery.
use se_types::{Result, SeError};
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum IdentityRole {
    CallerAgent,
    CallerProject,
    Target,
}
pub const CALLER_FIELDS: &[(&str, IdentityRole)] = &[
    ("agent_id", IdentityRole::CallerAgent),
    ("agentId", IdentityRole::CallerAgent),
    ("project_id", IdentityRole::CallerProject),
    ("projectId", IdentityRole::CallerProject),
    ("project", IdentityRole::CallerProject),
];
const AGENT_TARGET: &[(&str, IdentityRole)] = &[
    ("agent_id", IdentityRole::CallerAgent),
    ("agentId", IdentityRole::CallerAgent),
    ("project_id", IdentityRole::CallerProject),
    ("projectId", IdentityRole::CallerProject),
    ("project", IdentityRole::CallerProject),
    ("target_agent_id", IdentityRole::Target),
];
pub const MCP_IDENTITY_ARGUMENT_ROLES: &[(&str, &[(&str, IdentityRole)])] = &[
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
    ("stateengine_agent_launch", AGENT_TARGET),
    ("stateengine_agent_stop", AGENT_TARGET),
    ("stateengine_decision_list", CALLER_FIELDS),
    ("stateengine_decision_propose", CALLER_FIELDS),
];
pub fn fields(tool: &str) -> Result<&'static [(&'static str, IdentityRole)]> {
    MCP_IDENTITY_ARGUMENT_ROLES.iter().find_map(|(name, fields)| (*name == tool).then_some(*fields))
        .ok_or_else(|| SeError::invalid("MCP_IDENTITY_ARGUMENT_ROLES", &format!("an explicit caller/target field table for {tool}; no identity semantics are inferred")))
}
pub(super) fn describe(tool: &str, schema: &mut serde_json::Value) -> Result<()> {
    let mut descriptions = Vec::new();
    for (field, role) in fields(tool)? {
        let role = match role {
            IdentityRole::CallerAgent => "caller-agent",
            IdentityRole::CallerProject => "caller-project",
            IdentityRole::Target => "target",
        };
        descriptions.push(format!("{field}: {role}"));
        if let Some(property) = schema.get_mut("properties").and_then(|p| p.get_mut(field)) {
            property["description"] = serde_json::json!(role);
        }
    }
    schema["description"] = serde_json::json!(descriptions.join("; "));
    Ok(())
}
