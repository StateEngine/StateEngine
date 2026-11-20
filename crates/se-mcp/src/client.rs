//! How a launched agent reaches this host's MCP route: the server entry each
//! provider receives, and for Codex how that entry coexists with the login's
//! own `stateengine` registration, which `se init` adds so sessions the user
//! starts outside StateEngine can reach the project too.
use se_types::{Result, SeError, Secret};
use serde_json::{Value, json};

/// The name `se init` registers for sessions run outside StateEngine. Claude
/// agents use it too: their launch ignores every other registration.
pub const SERVER: &str = "stateengine";
/// The host's per-thread server for Codex agents, unless the user's config
/// already uses that name. Codex merges thread overrides into a login entry of
/// the same name, and a URL cannot join that entry's command.
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

/// Given Codex's effective configuration for the thread's directory, fit the
/// thread's overrides into it without touching the user's config: switch off
/// the login's own `stateengine` registration for this thread, and move the
/// host's server to the first managed name the configuration does not use, so
/// the agent sees exactly one StateEngine server and every user server stays.
pub fn codex_fit(effective: &Value, overrides: &mut Value) -> Result<()> {
    let invalid = |expected| SeError::invalid("Codex effective configuration", expected);
    let config = effective
        .get("config")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("a config object"))?;
    let empty = serde_json::Map::new();
    let servers = match config.get("mcp_servers") {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(servers)) => servers,
        Some(_) => return Err(invalid("mcp_servers as a table")),
    };
    if servers.contains_key(SERVER) {
        overrides[format!("mcp_servers.{SERVER}.enabled")] = Value::Bool(false);
    }
    // At most one more name than the table holds, so a free one always exists.
    let mut name = CODEX_AGENT_SERVER.to_owned();
    let mut number = 1;
    while servers.contains_key(&name) {
        number += 1;
        name = format!("{CODEX_AGENT_SERVER}-{number}");
    }
    if name != CODEX_AGENT_SERVER {
        let object = overrides
            .as_object_mut()
            .ok_or_else(|| invalid("thread overrides as an object"))?;
        let entry = object
            .remove(&format!("mcp_servers.{CODEX_AGENT_SERVER}"))
            .ok_or_else(|| invalid("the host's server entry in the thread overrides"))?;
        object.insert(format!("mcp_servers.{name}"), entry);
    }
    Ok(())
}
