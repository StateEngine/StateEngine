//! Literal app-server requests and per-launch overrides. Never replace the
//! user's CODEX_HOME, login, global settings, or selected sandbox implementation.
use super::codex_rpc::incompatible;
use crate::{HarnessRequest, ProviderInvocation};
use se_core::config_policy::{Approval, EffectiveSandbox, ResolvedProfile};
use se_proc::{LaunchMode, NetworkPolicy, WritePolicy};
use se_types::{Body, ProviderSessionId, Read, Result, SeError};
use serde_json::{Value, json};
use std::{ffi::OsString, path::Path};

pub struct CodexLaunch<'a> {
    pub request: &'a HarnessRequest,
    pub resolved: &'a ResolvedProfile,
    pub mcp_port: u16,
    pub socket: Option<&'a Path>,
}

pub fn initialize() -> Value {
    json!({"clientInfo": {
        "name": "stateengine", "title": "StateEngine", "version": env!("CARGO_PKG_VERSION")
    }, "capabilities": {"experimentalApi":true}})
}

fn approval(policy: &ResolvedProfile) -> &'static str {
    match policy.approval {
        Approval::Never => "never",
        Approval::OnRequest => "on-request",
        Approval::Untrusted => "untrusted",
    }
}

fn mode(policy: &ResolvedProfile) -> &'static str {
    match policy.sandbox {
        EffectiveSandbox::ReadOnly => "read-only",
        EffectiveSandbox::WorkspaceWrite => "workspace-write",
        EffectiveSandbox::Bypass => "danger-full-access",
    }
}

fn path(path: &Path) -> Result<&str> {
    if !path.is_absolute() {
        return Err(SeError::invalid("Codex path", "an absolute native path"));
    }
    path.to_str().ok_or_else(|| {
        incompatible(
            "the selected path is not UTF-8",
            "Select a UTF-8 project and data path.",
        )
    })
}

fn validate(launch: &CodexLaunch<'_>) -> Result<()> {
    let request = launch.request;
    let resolved = launch.resolved;
    if request.profile.provider != se_store::Provider::Codex
        || resolved.name != request.profile.named_profile
        || resolved.network != matches!(request.policy.network, NetworkPolicy::Allow)
    {
        return Err(SeError::invalid(
            "Codex profile",
            "the exact resolved saved Codex profile",
        ));
    }
    if request.mode == LaunchMode::Headless && resolved.approval != Approval::Never {
        return Err(incompatible(
            "the saved approval policy needs an attended decision UI",
            "Launch in a supported window or select a named profile with approval='never'.",
        ));
    }
    let matches = match (&resolved.sandbox, &request.policy.writes) {
        (EffectiveSandbox::ReadOnly, WritePolicy::ReadOnly { .. }) => {
            request.profile.permission == se_store::PermissionProfile::ReadOnly && !resolved.bypass
        }
        (EffectiveSandbox::WorkspaceWrite, WritePolicy::Workspace { .. }) => {
            request.profile.permission == se_store::PermissionProfile::WorkspaceWrite
                && !resolved.bypass
        }
        (EffectiveSandbox::Bypass, WritePolicy::NamedUnrestricted { profile }) => {
            request.profile.permission == se_store::PermissionProfile::NamedFullBypass
                && resolved.bypass
                && profile == &resolved.name
        }
        _ => false,
    };
    if !matches {
        return Err(SeError::invalid(
            "Codex policy",
            "matching provider and native write policies",
        ));
    }
    if resolved.sandbox == EffectiveSandbox::Bypass && !resolved.network {
        return Err(incompatible(
            "danger-full-access cannot enforce the selected offline network policy",
            "Select a sandboxed profile or explicitly save a named bypass profile with network enabled.",
        ));
    }
    Ok(())
}

fn sandbox(launch: &CodexLaunch<'_>) -> Result<Value> {
    validate(launch)?;
    Ok(match &launch.request.policy.writes {
        WritePolicy::ReadOnly { .. } => {
            json!({"type":"readOnly", "networkAccess":launch.resolved.network})
        }
        WritePolicy::Workspace { roots, scratch } => {
            let mut writable = roots
                .iter()
                .map(|root| path(root))
                .collect::<Result<Vec<_>>>()?;
            let scratch = path(scratch)?;
            if !writable.contains(&scratch) {
                writable.push(scratch);
            }
            json!({"type":"workspaceWrite", "writableRoots":writable,
                "networkAccess":launch.resolved.network,
                "excludeTmpdirEnvVar":true, "excludeSlashTmp":true})
        }
        WritePolicy::NamedUnrestricted { .. } => json!({"type":"dangerFullAccess"}),
    })
}

/// Initialization/resumption carries the same policy as every new turn.
/// An unreadable saved thread never silently starts a new conversation.
pub fn thread(launch: &CodexLaunch<'_>) -> Result<(&'static str, Value)> {
    let policy = sandbox(launch)?;
    let mut config = json!({
        "sandbox_workspace_write": {
            "network_access":launch.resolved.network,
            "exclude_tmpdir_env_var":true,
            "exclude_slash_tmp":true,
        },
        "sandbox_read_only": {"network_access":launch.resolved.network},
    });
    if let Some(roots) = policy.get("writableRoots") {
        config["sandbox_workspace_write"]["writable_roots"] = roots.clone();
    }
    if launch.mcp_port == 0 {
        return Err(SeError::invalid(
            "Codex MCP",
            "this host's bound loopback port",
        ));
    }
    let secret = |value: &se_types::Secret| {
        std::str::from_utf8(value.expose())
            .map_err(|_| {
                SeError::invalid("Codex MCP credential", "the host-issued ASCII credential")
            })
            .map(str::to_owned)
    };
    // This object travels only through the private provider RPC. Neither secret
    // enters argv, the environment, a replacement CODEX_HOME or a config file.
    config["mcp_servers.stateengine"] = json!({
        "url":format!("http://127.0.0.1:{}/mcp", launch.mcp_port),
        "enabled":true, "required":true,
        // Match Claude's host-only allowedTools grant. Recipient capabilities
        // are still checked by this authenticated host; other servers retain
        // their own approval policy and the saved sandbox stays unchanged.
        "default_tools_approval_mode":"approve",
        "http_headers": {
            "Authorization":format!("Bearer {}", secret(&launch.request.mcp_bearer)?),
            "X-StateEngine-Session-Proof":secret(&launch.request.launch_credential)?,
        }
    });
    let local_cwd = launch.request.cwd.to_local()?;
    let cwd = path(&local_cwd)?;
    let mut params = json!({
        "cwd": cwd,
        "approvalPolicy":approval(launch.resolved),
        "sandbox":mode(launch.resolved), "config":config,
        // Resumption otherwise restores the prior launch's scratch directory
        // as an implicit writable root, even when config overrides are supplied.
        "runtimeWorkspaceRoots":policy.get("writableRoots").cloned()
            .unwrap_or_else(|| json!([cwd])),
    });
    if let Some(model) = &launch.request.profile.model {
        params["model"] = json!(model);
    }
    match &launch.request.resume {
        Read::Absent { .. } => Ok(("thread/start", params)),
        Read::Present { value } => {
            params["threadId"] = json!(value.as_str());
            // Bound the resume response; history is retrieved through its own
            // paginated consumer, never retained as an unbounded RPC reply.
            params["excludeTurns"] = json!(true);
            Ok(("thread/resume", params))
        }
        Read::Unreadable { reason, .. } => {
            Err(se_core::scope::unreadable("saved Codex thread", reason))
        }
        Read::Unknown { what } => Err(se_core::scope::unreadable("saved Codex thread", what)),
    }
}

/// Provider readiness includes its actual conversation and effective policy,
/// not merely successful delivery of our requested configuration.
pub fn verify_thread(launch: &CodexLaunch<'_>, result: &Value) -> Result<ProviderSessionId> {
    let mut expected = sandbox(launch)?;
    // Stock app-server makes cwd an implicit writable root and omits it from
    // the policy echo. Keep additional roots exact rather than widening them.
    let cwd = launch.request.cwd.to_local()?;
    if let Some(roots) = expected
        .get_mut("writableRoots")
        .and_then(Value::as_array_mut)
    {
        roots.retain(|root| root.as_str() != cwd.to_str());
    }
    if result.get("approvalPolicy") != Some(&json!(approval(launch.resolved)))
        || result.get("sandbox") != Some(&expected)
        || result.get("cwd") != Some(&json!(path(&launch.request.cwd.to_local()?)?))
    {
        return Err(incompatible(
            "the provider did not echo the exact selected cwd, approval and sandbox policy",
            "Correct the provider/profile configuration; the host will not widen policy to continue.",
        ));
    }
    let id = result
        .pointer("/thread/id")
        .and_then(Value::as_str)
        .ok_or_else(|| SeError::invalid("Codex readiness", "the provider's actual thread.id"))?;
    let id = ProviderSessionId::new(id.to_owned())?;
    if let Read::Present { value } = &launch.request.resume
        && value != &id
    {
        return Err(SeError::invalid(
            "Codex resume",
            "the exact saved provider thread",
        ));
    }
    Ok(id)
}

pub fn turn(
    launch: &CodexLaunch<'_>,
    conversation: &ProviderSessionId,
    body: &Body,
) -> Result<Value> {
    let mut params = json!({"threadId":conversation.as_str(),
        "input":[{"type":"text", "text":body.as_str()}],
        "cwd":path(&launch.request.cwd.to_local()?)?,
        "approvalPolicy":approval(launch.resolved), "sandboxPolicy":sandbox(launch)?});
    if let Some(model) = &launch.request.profile.model {
        params["model"] = json!(model);
    }
    if let Some(effort) = &launch.request.profile.effort {
        params["effort"] = json!(effort);
    }
    Ok(params)
}

fn checked_turn(id: &str) -> Result<&str> {
    if id.is_empty() || id.len() > 1024 || id.chars().any(char::is_control) {
        return Err(SeError::invalid(
            "Codex turn",
            "the bounded actual provider turn ID",
        ));
    }
    Ok(id)
}

/// The caller supplies the actual current turn, never a guessed latest turn.
/// A raced completion remains the provider's precondition refusal.
pub fn steer(conversation: &ProviderSessionId, expected_turn: &str, body: &Body) -> Result<Value> {
    Ok(
        json!({"threadId":conversation.as_str(), "expectedTurnId":checked_turn(expected_turn)?,
        "input":[{"type":"text", "text":body.as_str()}]}),
    )
}

/// This request's RPC acknowledgment does not prove turn or process closure.
pub fn interrupt(conversation: &ProviderSessionId, active_turn: &str) -> Result<Value> {
    Ok(json!({"threadId":conversation.as_str(), "turnId":checked_turn(active_turn)?}))
}

/// Only non-secret provider policy enters argv. MCP configuration and both
/// first-use credentials are supplied later through the private thread RPC.
pub fn invocation(
    launch: &CodexLaunch<'_>,
    mut environment: Vec<(OsString, OsString)>,
) -> Result<ProviderInvocation> {
    validate(launch)?;
    let mut arguments = Vec::new();
    let settings = [
        ("approval_policy", json!(approval(launch.resolved))),
        ("sandbox_mode", json!(mode(launch.resolved))),
    ];
    // Values are TOML-compatible scalar/array literals. No string interpolation
    // into shell commands and no per-launch replacement config home.
    for (key, value) in settings {
        arguments.push("-c".into());
        arguments.push(format!("{key}={value}").into());
    }
    arguments.extend([
        "app-server".into(),
        "--listen".into(),
        match launch.socket {
            Some(socket) => format!("unix://{}", path(socket)?).into(),
            None => "stdio://".into(),
        },
    ]);
    environment.retain(|(name, _)| {
        let name = name.to_string_lossy().to_ascii_uppercase();
        name != "SE_SESSION" && !name.starts_with("STATEENGINE_") && !name.starts_with("SECODE_")
    });
    // Match Claude's hook/stdio route: this is the newly issued public handle,
    // never the secret pin or an inherited session's authority. External MCP
    // services resolve it through the same protected native credential store.
    environment.push((
        "SE_SESSION".into(),
        launch.request.identity.session.as_str().into(),
    ));
    Ok(ProviderInvocation {
        executable: launch.request.executable.clone(),
        arguments,
        environment: se_proc::Environment {
            entries: environment,
        },
    })
}

/// Codex receives its own login/configuration variables, never another
/// provider's API credentials or operator/fleet authority.
pub fn provider_environment() -> Vec<(OsString, OsString)> {
    const ALLOWED: &[&str] = &[
        "PATH",
        "HOME",
        "USER",
        "LOGNAME",
        "SHELL",
        "LANG",
        "TZ",
        "TMPDIR",
        "TERM",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_CACHE_HOME",
        "XDG_STATE_HOME",
        "XDG_RUNTIME_DIR",
        "CODEX_HOME",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "SystemRoot",
        "windir",
        "ComSpec",
        "PATHEXT",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "TEMP",
        "TMP",
        "ProgramData",
        "ProgramFiles",
        "ProgramW6432",
        "DISPLAY",
        "XAUTHORITY",
    ];
    std::env::vars_os()
        .filter(|(name, _)| {
            let name = name.to_string_lossy();
            ALLOWED
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(&name))
                || name.starts_with("LC_")
        })
        .collect()
}
