//! Headless Claude launch plan (section 40 §9.3, H09/H10). Pure functions: the
//! coordinator supplies trusted host facts and performs every file and process
//! effect. Nothing here mutates global Claude settings or the user's login.
//!
//! Per launch: one settings file holding only the fixed hook mappings, and one
//! MCP config naming this host's loopback /mcp with the session bearer. Both are
//! protected launch files; the bearer never enters argv or the environment,
//! which carries only the `ses_` handle hooks resolve. Claude then runs as
//! `claude -p` with stream-json input and output, so the host can write tasks
//! and mail as user messages and read readiness from the provider's own echo.
use crate::{ConfigPlan, HarnessRequest, OwnedLaunchFile, ProviderInvocation};
use se_types::{Body, NativePath, ProviderSessionId, Read, Result, SeError, Secret};
use serde_json::{Value, json};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

/// The MCP server name Claude prefixes onto tool names (mcp__stateengine__*).
pub const MCP_SERVER: &str = "stateengine";
const SETTINGS_FILE: &str = "claude-settings.json";
const MCP_FILE: &str = "claude-mcp.json";

/// Trusted facts the coordinator owns; none come from provider input.
pub struct ClaudeLaunch<'a> {
    pub request: &'a HarnessRequest,
    /// The installed se executable hooks call, never resolved from PATH.
    pub se_executable: &'a Path,
    pub state_home: &'a Path,
    /// The protected per-launch directory the coordinator creates and removes.
    pub launch_directory: &'a Path,
    pub mcp_port: u16,
    pub conversation: &'a ProviderSessionId,
    /// True resumes the verified saved conversation; false starts it new.
    pub resume: bool,
}

/// The two protected launch files. The coordinator writes them owner-only
/// before exec and removes them after the process is witnessed closed.
pub fn configuration(launch: &ClaudeLaunch<'_>) -> Result<ConfigPlan> {
    let hook = |event: &str| -> Value {
        json!([{"hooks": [{"type": "command", "command": hook_command(launch, event)}]}])
    };
    let settings = json!({
        "hooks": {
            "SessionStart": hook("session-start"),
            "UserPromptSubmit": hook("prompt"),
            "Stop": hook("stop"),
            "SubagentStop": hook("stop"),
            "StopFailure": hook("stop-failure"),
        }
    });
    let mut bearer = b"Bearer ".to_vec();
    bearer.extend_from_slice(launch.request.mcp_bearer.expose());
    let bearer = String::from_utf8(bearer)
        .map_err(|_| SeError::invalid("session credential", "printable bearer bytes"))?;
    let mcp = json!({
        "mcpServers": {
            MCP_SERVER: {
                "type": "http",
                "url": format!("http://127.0.0.1:{}/mcp", launch.mcp_port),
                "headers": {"Authorization": bearer},
            }
        }
    });
    Ok(ConfigPlan {
        edits: Vec::new(),
        ephemeral_files: vec![
            file(&launch.launch_directory.join(SETTINGS_FILE), &settings)?,
            file(&launch.launch_directory.join(MCP_FILE), &mcp)?,
        ],
    })
}

/// Literal argv and environment. `environment` is the host-built base (OS
/// transport, HOME and the provider's own login); this adds only the session
/// handle the hooks present back to this host.
pub fn invocation(
    launch: &ClaudeLaunch<'_>,
    environment: Vec<(OsString, OsString)>,
) -> Result<ProviderInvocation> {
    let request = launch.request;
    let path = |name: &str| launch.launch_directory.join(name).into_os_string();
    let mut arguments: Vec<OsString> = if request.mode == se_proc::LaunchMode::Window {
        Vec::new()
    } else {
        [
            "-p",
            "--input-format",
            "stream-json",
            "--output-format",
            "stream-json",
            "--verbose",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    };
    arguments.extend([
        "--settings".into(),
        path(SETTINGS_FILE),
        "--mcp-config".into(),
        path(MCP_FILE),
        "--strict-mcp-config".into(),
        if launch.resume {
            "--resume"
        } else {
            "--session-id"
        }
        .into(),
        launch.conversation.as_str().into(),
        "--permission-mode".into(),
        permission_mode(request.profile.permission).into(),
        // Only this host's tools are pre-approved; no human answers prompts.
        "--allowedTools".into(),
        format!("mcp__{MCP_SERVER}").into(),
    ]);
    if let Some(model) = &request.profile.model {
        arguments.extend(["--model".into(), model.into()]);
    }
    if request.mode == se_proc::LaunchMode::Window {
        // Task text is a positional prompt, even when it resembles a permission
        // flag. Keep every host-owned option before the end-of-options marker.
        arguments.extend(["--".into(), request.initial_input.as_str().into()]);
    }
    let mut entries: Vec<_> = environment
        .into_iter()
        .filter(|(name, _)| !is_session_variable(name))
        .collect();
    // Hooks present only the session handle; se resolves the secret from the
    // owner-only launch pin. The token itself never enters the environment.
    entries.push((
        "SE_SESSION".into(),
        request.identity.session.as_str().into(),
    ));
    Ok(ProviderInvocation {
        executable: request.executable.clone(),
        arguments,
        environment: se_proc::Environment { entries },
    })
}

/// Headless mode has no one to answer a prompt: an unapproved action is
/// refused, never silently allowed. Only a named saved profile bypasses.
fn permission_mode(profile: se_store::PermissionProfile) -> &'static str {
    match profile {
        se_store::PermissionProfile::ReadOnly => "default",
        se_store::PermissionProfile::WorkspaceWrite => "acceptEdits",
        se_store::PermissionProfile::NamedFullBypass => "bypassPermissions",
    }
}

fn is_session_variable(name: &OsString) -> bool {
    let name = name.to_string_lossy().to_ascii_uppercase();
    name == "SE_SESSION" || name.starts_with("STATEENGINE_") || name.starts_with("SECODE_")
}

/// One stream-json user message, newline-terminated, for stdin.
pub fn input_frame(body: &Body) -> Result<Vec<u8>> {
    let message = json!({
        "type": "user",
        "message": {"role": "user", "content": [{"type": "text", "text": body.as_str()}]},
    });
    let mut frame = serde_json::to_vec(&message)
        .map_err(|e| se_core::scope::unreadable("Claude input frame", &e.to_string()))?;
    frame.push(b'\n');
    Ok(frame)
}

#[derive(Debug, Eq, PartialEq)]
pub enum Readiness {
    /// The provider echoed the exact selected conversation.
    Ready,
    /// An ordinary stream line before the init echo.
    NotYet,
    /// The provider started a different conversation than the one selected.
    Mismatch { echoed: String },
}

/// Readiness is the provider's own `system/init` echo, never prepared argv.
pub fn readiness(line: &[u8], conversation: &ProviderSessionId) -> Readiness {
    let Ok(value) = serde_json::from_slice::<Value>(line) else {
        return Readiness::NotYet;
    };
    if value.get("type").and_then(Value::as_str) != Some("system")
        || value.get("subtype").and_then(Value::as_str) != Some("init")
    {
        return Readiness::NotYet;
    }
    match value.get("session_id").and_then(Value::as_str) {
        Some(echoed) if echoed == conversation.as_str() => Readiness::Ready,
        Some(echoed) => Readiness::Mismatch {
            echoed: echoed.to_owned(),
        },
        None => Readiness::NotYet,
    }
}

/// Where Claude writes this conversation's transcript: under its config home,
/// in a directory named by its native project-slug convention. Long slugs use
/// the first 200 UTF-16 units and a base-36 signed string hash of the full cwd.
/// The capture pin still verifies the file itself; this only names where to look.
pub fn transcript_path(
    config_home: &Path,
    cwd: &Path,
    conversation: &ProviderSessionId,
) -> PathBuf {
    let cwd = cwd.to_string_lossy();
    let mut slug: String = cwd
        .encode_utf16()
        .map(|unit| match unit {
            48..=57 | 65..=90 | 97..=122 => char::from(unit as u8),
            _ => '-',
        })
        .collect();
    if slug.len() > 200 {
        let hash = cwd.encode_utf16().fold(0_i32, |hash, unit| {
            hash.wrapping_mul(31).wrapping_add(i32::from(unit))
        });
        let mut value = hash.unsigned_abs();
        let mut suffix = Vec::new();
        loop {
            suffix.push(char::from(
                b"0123456789abcdefghijklmnopqrstuvwxyz"[(value % 36) as usize],
            ));
            value /= 36;
            if value == 0 {
                break;
            }
        }
        slug.truncate(200);
        slug.push('-');
        slug.extend(suffix.into_iter().rev());
    }
    config_home
        .join("projects")
        .join(slug)
        .join(format!("{}.jsonl", conversation.as_str()))
}

/// Claude runs hook commands through the platform shell; quote each word.
fn hook_command(launch: &ClaudeLaunch<'_>, event: &str) -> String {
    [
        launch.se_executable.to_string_lossy().as_ref(),
        "--home",
        launch.state_home.to_string_lossy().as_ref(),
        "hook",
        "claude",
        event,
    ]
    .iter()
    .map(|word| shell_word(word))
    .collect::<Vec<_>>()
    .join(" ")
}

fn shell_word(word: &str) -> String {
    if cfg!(windows) {
        format!("\"{}\"", word.replace('"', "\\\""))
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

fn file(path: &Path, value: &Value) -> Result<OwnedLaunchFile> {
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|e| se_core::scope::unreadable("Claude launch file", &e.to_string()))?;
    Ok(OwnedLaunchFile {
        path: NativePath::from_local(path.to_path_buf())?,
        contents: Secret::new(bytes)?,
    })
}

/// Host-environment names a provider legitimately needs: OS transport, the
/// user's home and the provider's own login. Never fleet or session names.
const ENVIRONMENT: &[&str] = &[
    "PATH",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "LANG",
    "TZ",
    "TMPDIR",
    "TERM",
    "DISPLAY",
    "XAUTHORITY",
    "WAYLAND_DISPLAY",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "XDG_RUNTIME_DIR",
    "CLAUDE_CONFIG_DIR",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_BASE_URL",
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
];

/// A new conversation reuses the session's own UUID, so its identity is fixed
/// by the reservation before any provider runs. Resume uses the saved one.
pub fn conversation(request: &HarnessRequest) -> Result<ProviderSessionId> {
    match &request.resume {
        Read::Present { value } => Ok(value.clone()),
        Read::Absent { .. } => ProviderSessionId::new(session_uuid(request)?),
        Read::Unreadable { reason, .. } => Err(se_core::scope::unreadable(
            "saved Claude conversation",
            reason,
        )),
        Read::Unknown { what } => Err(se_core::scope::unreadable(
            "saved Claude conversation",
            what,
        )),
    }
}

pub(crate) fn session_uuid(request: &HarnessRequest) -> Result<&str> {
    request
        .identity
        .session
        .as_str()
        .strip_prefix("ses_")
        .ok_or_else(|| SeError::invalid("session id", "a canonical ses_<UUID> session"))
}

/// The base environment handed to the provider, built from an allowlist.
pub fn provider_environment() -> Vec<(OsString, OsString)> {
    std::env::vars_os()
        .filter(|(name, _)| {
            let name = name.to_string_lossy();
            ENVIRONMENT
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(&name))
                || name.starts_with("LC_")
        })
        .collect()
}

/// Where this provider's Claude config lives, as the child will see it.
pub fn config_home(environment: &[(OsString, OsString)]) -> Result<PathBuf> {
    let value = |wanted: &str| {
        environment
            .iter()
            .find(|(name, _)| name.to_string_lossy().eq_ignore_ascii_case(wanted))
            .map(|(_, value)| PathBuf::from(value))
    };
    value("CLAUDE_CONFIG_DIR")
        .or_else(|| value("HOME").map(|home| home.join(".claude")))
        .or_else(|| value("USERPROFILE").map(|home| home.join(".claude")))
        .ok_or_else(|| SeError::invalid("Claude config home", "HOME or CLAUDE_CONFIG_DIR"))
}
