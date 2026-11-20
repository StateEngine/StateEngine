//! How a launched agent reaches this host's MCP route: the server entry each
//! provider receives, and for Codex how that entry coexists with the login's
//! own `stateengine` registration, which `se init` adds so sessions the user
//! starts outside StateEngine can reach the project too.
use se_types::{Result, SeError, Secret};
use serde_json::{Value, json};

/// The name `se init` registers for sessions run outside StateEngine. Claude
/// agents use it too: their launch ignores every other registration.
pub const SERVER: &str = "stateengine";
/// The host's per-thread server for Codex agents. Codex merges thread
/// overrides into the login's entry of the same name, and a URL cannot join
/// that entry's command, so the agent's server has a name of its own.
pub const CODEX_AGENT_SERVER: &str = "stateengine-agent";

fn route(port: u16) -> String {
    format!("http://127.0.0.1:{port}/mcp")
}

fn ascii(value: &Secret) -> Result<&str> {
    std::str::from_utf8(value.expose())
        .map_err(|_| SeError::invalid("MCP credential", "the host-issued ASCII credential"))
}

/// Claude's MCP config file, whose single server is this host.
pub fn claude_config(port: u16, bearer: &Secret) -> Result<Value> {
    Ok(json!({
        "mcpServers": {
            SERVER: {
                "type": "http",
                "url": route(port),
                "headers": {"Authorization": format!("Bearer {}", ascii(bearer)?)},
            }
        }
    }))
}

/// The Codex thread override that adds this host's server. It travels only
/// through the private provider RPC: neither credential enters argv, the
/// environment, a replacement CODEX_HOME or a config file.
pub fn codex_agent_server(port: u16, bearer: &Secret, proof: &Secret) -> Result<(String, Value)> {
    Ok((
        format!("mcp_servers.{CODEX_AGENT_SERVER}"),
        json!({
            "url": route(port),
            "enabled": true, "required": true,
            // Match Claude's host-only allowedTools grant. Recipient
            // capabilities are still checked by this authenticated host; other
            // servers keep their own approval policy and the sandbox is unchanged.
            "default_tools_approval_mode": "approve",
            "http_headers": {
                "Authorization": format!("Bearer {}", ascii(bearer)?),
                "X-StateEngine-Session-Proof": ascii(proof)?,
            }
        }),
    ))
}

/// Given Codex's effective configuration for the thread's directory, the
/// override that switches off the login's own registration for this thread,
/// so the agent sees exactly one StateEngine server. The user's config is not
/// edited, and sessions outside StateEngine still use that registration.
pub fn codex_login_server_off(effective: &Value) -> Result<Option<(String, Value)>> {
    let config = effective
        .get("config")
        .and_then(Value::as_object)
        .ok_or_else(|| SeError::invalid("Codex effective configuration", "a config object"))?;
    match config.get("mcp_servers") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Object(servers)) if servers.contains_key(SERVER) => Ok(Some((
            format!("mcp_servers.{SERVER}.enabled"),
            Value::Bool(false),
        ))),
        Some(Value::Object(_)) => Ok(None),
        Some(_) => Err(SeError::invalid(
            "Codex effective configuration",
            "mcp_servers as a table",
        )),
    }
}
