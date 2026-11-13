//! Native settings discovery without running a task, hooks, plugins or MCP.
//! Safe mode retains Claude's permission sources and managed policy. The final
//! provider runs normally; only an unset headless workspace mode gets acceptEdits.
use super::completion::MAX_LINE;
use se_types::{Result, SeError};
use serde_json::Value;
use std::{ffi::OsString, path::Path, process::Stdio, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

pub(super) async fn has_saved_mode(
    command: &Path,
    cwd: &Path,
    environment: &[(OsString, OsString)],
    timeout: Duration,
) -> Result<bool> {
    if timeout.is_zero() {
        return Err(invalid("an unexpired native settings deadline"));
    }
    let until = tokio::time::Instant::now() + timeout;
    let query_until = until - (timeout / 10).min(Duration::from_millis(500));
    let mut child = tokio::process::Command::new(command)
        .args([
            "--safe-mode",
            "-p",
            "--input-format",
            "stream-json",
            "--output-format",
            "stream-json",
            "--verbose",
            "--no-session-persistence",
        ])
        .current_dir(cwd)
        .env_clear()
        .envs(environment.iter().cloned())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| unreadable(&e.to_string()))?;
    let checked = tokio::time::timeout_at(query_until, async {
        let mut input = child.stdin.take().ok_or_else(|| invalid("native settings stdin"))?;
        input.write_all(b"{\"type\":\"control_request\",\"request_id\":\"settings\",\"request\":{\"subtype\":\"get_settings\"}}\n")
            .await.map_err(|e| unreadable(&e.to_string()))?;
        let output = child.stdout.take().ok_or_else(|| invalid("native settings stdout"))?;
        let mut output = BufReader::new(output.take(MAX_LINE as u64 + 1));
        let mut line = Vec::new();
        let mut total = 0;
        loop {
            line.clear();
            let read = output.read_until(b'\n', &mut line).await.map_err(|e| unreadable(&e.to_string()))?;
            total += read;
            if total > MAX_LINE {
                return Err(invalid("a bounded native settings snapshot"));
            }
            if read == 0 || !line.ends_with(b"\n") {
                return Err(invalid("a complete native settings response; update Claude Code and retry"));
            }
            let row: Value = serde_json::from_slice(&line).map_err(|e| unreadable(&e.to_string()))?;
            if row.get("type").and_then(Value::as_str) != Some("control_response")
                || row.pointer("/response/request_id").and_then(Value::as_str) != Some("settings")
            {
                continue;
            }
            if row.pointer("/response/subtype").and_then(Value::as_str) != Some("success") {
                return Err(invalid("successful native settings discovery; check or update Claude Code and retry"));
            }
            return saved_mode(row.pointer("/response/response").ok_or_else(|| invalid("Claude's settings snapshot"))?);
        }
    }).await;
    // Retained direct child only. Prove its exit on both success and refusal.
    let killed = child.start_kill();
    if !matches!(
        tokio::time::timeout_at(until, child.wait()).await,
        Ok(Ok(_))
    ) {
        return Err(invalid(
            "the native settings probe's witnessed exit before retrying",
        ));
    }
    killed.map_err(|e| unreadable(&e.to_string()))?;
    checked.map_err(|_| {
        invalid("native settings within the launch deadline; retry or check Claude Code")
    })?
}

fn saved_mode(settings: &Value) -> Result<bool> {
    if let Some(errors) = settings.get("errors") {
        let errors = errors
            .as_array()
            .ok_or_else(|| invalid("a readable native settings error list"))?;
        if let Some(first) = errors.first() {
            return Err(unreadable(&format!(
                "Claude reported {} settings read or validation error(s), first in {}. Fix the settings in Claude Code and retry; no permission fallback was applied",
                errors.len(),
                first
                    .get("file")
                    .and_then(Value::as_str)
                    .unwrap_or("native settings"),
            )));
        }
    }
    let effective = settings
        .get("effective")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("Claude's effective settings snapshot"))?;
    if settings.get("sources").and_then(Value::as_array).is_none() {
        return Err(invalid("Claude's settings source list"));
    }
    let Some(permissions) = effective.get("permissions") else {
        return Ok(false);
    };
    let permissions = permissions
        .as_object()
        .ok_or_else(|| invalid("Claude's permission settings"))?;
    let Some(mode) = permissions.get("defaultMode") else {
        return Ok(false);
    };
    if mode.as_str().is_none_or(str::is_empty) {
        return Err(invalid("a readable saved Claude permission mode"));
    }
    Ok(true)
}

fn invalid(expected: &str) -> SeError {
    SeError::invalid("Claude permission settings", expected)
}
fn unreadable(reason: &str) -> SeError {
    se_core::scope::unreadable("Claude permission settings", reason)
}
