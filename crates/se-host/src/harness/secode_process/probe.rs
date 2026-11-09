use super::{incompatible, unreadable};
use crate::client::lease::Deadline;
use se_types::Result;
use serde_json::Value;
use std::{ffi::OsString, path::Path, process::Stdio};
use tokio::io::AsyncReadExt;

pub async fn version(cli: &Path, deadline: &Deadline) -> Result<String> {
    let bytes = command(cli, &["--version".into()], deadline).await?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| incompatible("the CLI version is not UTF-8"))?
        .trim();
    if !value.starts_with("secode ")
        || value.len() > 4096
        || value
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(incompatible(
            "the CLI version has an unsupported shape or exceeds four KiB",
        ));
    }
    Ok(value.to_owned())
}

pub async fn capabilities(server: &Path, deadline: &Deadline) -> Result<Value> {
    let bytes = command(server, &["--external-host-capabilities".into()], deadline).await?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
        incompatible("the server did not return a readable external-host capability object")
    })?;
    for (pointer, expected) in [
        (
            "/schema",
            serde_json::json!("secode.external-host-capabilities.v1"),
        ),
        ("/external_host", serde_json::json!(true)),
        ("/stateengine/owner", serde_json::json!("external")),
        (
            "/stateengine/embedded_owner_composed",
            serde_json::json!(false),
        ),
        (
            "/stateengine/configured_mcp_transports",
            serde_json::json!("unchanged"),
        ),
        (
            "/service/argv",
            serde_json::json!([
                "serve-service",
                "--service",
                "<profile>",
                "--port",
                "0",
                "--external-host"
            ]),
        ),
        (
            "/service/profile_init_argv",
            serde_json::json!(["init-profile", "--service", "<new-absolute-profile>"]),
        ),
        (
            "/service/readiness/file",
            serde_json::json!("serve-ready.json"),
        ),
        (
            "/service/readiness/schema",
            serde_json::json!("secode.product.ready.v2"),
        ),
        (
            "/service/readiness/endpoint_field",
            serde_json::json!("observed_endpoint"),
        ),
        (
            "/service/readiness/authenticated_health_path",
            serde_json::json!("/api/health"),
        ),
        ("/initial_input/key_type", serde_json::json!("MessageId")),
        (
            "/initial_input/cli_argument",
            serde_json::json!("--input-id"),
        ),
        (
            "/initial_input/acceptance_path",
            serde_json::json!("/api/session/{sessionID}/input/{messageID}"),
        ),
        (
            "/initial_input/uncertain_write",
            serde_json::json!("pending-no-replay"),
        ),
        (
            "/native_notice/offer_path",
            serde_json::json!("/api/session/{sessionID}/stateengine/notice"),
        ),
        (
            "/native_notice/binding_path",
            serde_json::json!("/api/session/{sessionID}/stateengine/notice"),
        ),
        (
            "/native_notice/acceptance_path",
            serde_json::json!("/api/session/{sessionID}/input/{messageID}"),
        ),
        ("/native_notice/offer_method", serde_json::json!("POST")),
        ("/native_notice/message_limit", serde_json::json!(32)),
        ("/native_notice/body_delivery", serde_json::json!(false)),
    ] {
        if value.pointer(pointer) != Some(&expected) {
            return Err(incompatible(format!(
                "required capability {pointer} is missing or incompatible"
            )));
        }
    }
    let signals = value
        .pointer("/service/shutdown")
        .and_then(Value::as_array)
        .ok_or_else(|| incompatible("service shutdown capabilities are absent"))?;
    let signal = if cfg!(windows) { "Ctrl+C" } else { "SIGINT" };
    if !signals.iter().any(|found| found.as_str() == Some(signal)) {
        return Err(incompatible(
            "the service does not advertise supported native cancellation",
        ));
    }
    Ok(value)
}

pub fn supports_resume(value: &Value) -> bool {
    value.pointer("/native_notice/resume")
        == Some(&serde_json::json!({
            "method":"POST", "path":"/api/session/{sessionID}/stateengine/resume",
            "fences":["service","targetID","binding","holdID"],
            "admits_input":false,"starts_execution":false
        }))
}

/// Short, finite read-only commands. Service/client creation uses the native
/// coordinator arena instead. Output is bounded before parsing or diagnostics.
pub async fn command(
    executable: &Path,
    arguments: &[OsString],
    deadline: &Deadline,
) -> Result<Vec<u8>> {
    let mut child = tokio::process::Command::new(executable)
        .args(arguments)
        .env_clear()
        .envs(super::provider_environment())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| unreadable("SE Code command", e))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| unreadable("SE Code command", "stdout custody is absent"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| unreadable("SE Code command", "stderr custody is absent"))?;
    let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline.at()), async {
        tokio::try_join!(bounded(stdout), bounded(stderr), async {
            child
                .wait()
                .await
                .map_err(|e| unreadable("SE Code command exit", e))
        })
    })
    .await;
    match result {
        Ok(Ok((output, _, status))) if status.success() => Ok(output),
        Ok(Ok((_, _, status))) => Err(incompatible(format!(
            "selected native command exited with {status}"
        ))),
        failed => {
            let cleanup = child.kill().await;
            Err(unreadable(
                "SE Code command",
                format!(
                    "probe failed or exceeded its bound: {failed:?}; direct-child cleanup: {cleanup:?}"
                ),
            ))
        }
    }
}
async fn bounded(stream: impl tokio::io::AsyncRead + Unpin) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    stream
        .take(65537)
        .read_to_end(&mut bytes)
        .await
        .map_err(|e| unreadable("SE Code command output", e))?;
    if bytes.len() > 65536 {
        return Err(unreadable(
            "SE Code command output",
            "output exceeds 64 KiB",
        ));
    }
    Ok(bytes)
}
