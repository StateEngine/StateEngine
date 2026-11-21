//! Provider framing, output drains and bounded executable probes.
use super::{Binding, READ_CHUNK, claude};
use crate::{CallContext, ProviderStream, StreamRead};
use se_types::{Body, Result, SeError};
use std::{ffi::OsString, path::Path, process::Output, sync::Arc, time::Duration};

pub(super) async fn write_frame(binding: &Binding, body: &Body, cx: &CallContext) -> Result<()> {
    let frame = claude::input_frame(body)?;
    let expected = frame.len();
    let written = binding
        .io
        .write(&binding.transport, frame, copy(cx))
        .await?;
    match written.failure {
        // A frame counts as written only when all of its bytes were accepted.
        None if written.completed_bytes as usize == expected => Ok(()),
        None => Err(SeError::invalid(
            "Claude input",
            "the complete stream-json frame",
        )),
        Some(error) => Err(SeError::from(error)),
    }
}

/// Keep one output stream flowing until the provider closes it. Bytes are
/// activity, not captured turns, so they are read and released.
pub(super) async fn drain(
    binding: Arc<Binding>,
    stream: ProviderStream,
    generation: se_types::Generation,
    initial: Vec<u8>,
) {
    let mut frames = super::completion::Frames::default();
    if stream == ProviderStream::Output {
        frames.push(&initial, &binding);
    }
    loop {
        let cx = CallContext {
            generation,
            timeout: Duration::from_secs(24 * 60 * 60),
            cancellation: Arc::new(crate::CancellationState { _private: () }),
        };
        match binding
            .io
            .read(&binding.transport, stream, READ_CHUNK, cx)
            .await
        {
            Ok(StreamRead::Bytes(bytes)) => {
                if stream == ProviderStream::Output {
                    frames.push(&bytes, &binding);
                }
            }
            Ok(StreamRead::Eof | StreamRead::Failed { .. }) => return,
            // Only this loop's own day-long idle bound re-arms the read; any
            // other failure ends the drain instead of spinning on it.
            Err(error) if matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(_)) => {}
            Err(_) => return,
        }
    }
}

fn copy(cx: &CallContext) -> CallContext {
    CallContext {
        generation: cx.generation,
        timeout: cx.timeout,
        cancellation: Arc::clone(&cx.cancellation),
    }
}

pub(super) fn within(cx: &CallContext, remaining: Duration) -> CallContext {
    CallContext {
        timeout: remaining.min(cx.timeout),
        ..copy(cx)
    }
}

pub(super) async fn version_output(command: &Path, timeout: Duration) -> Result<String> {
    let output = probe_output(
        command,
        &["--version"],
        None,
        timeout,
        "Claude version probe",
    )
    .await?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub(super) async fn authentication(
    command: &Path,
    environment: &[(OsString, OsString)],
    timeout: Duration,
) -> Result<()> {
    let output = probe_output(
        command,
        &["auth", "status", "--json"],
        Some(environment),
        timeout,
        "Claude authentication status",
    )
    .await?;
    authentication_status(&output.stdout, output.status.code())
}

pub(super) async fn plugin(
    command: &Path,
    plugin: &Path,
    environment: &[(OsString, OsString)],
    timeout: Duration,
) -> Result<()> {
    let path = plugin.to_str().ok_or_else(|| {
        SeError::invalid("Claude plugin path", "a provider-supported Unicode path")
    })?;
    let output = probe_output(
        command,
        &["plugin", "validate", path],
        Some(environment),
        timeout,
        "Claude mail plugin validation",
    )
    .await?;
    if output.status.success() {
        Ok(())
    } else {
        Err(SeError::invalid(
            "Claude mail plugin",
            "installed provider support for the bundled mod",
        ))
    }
}

const SIGNED_OUT: &str = "you are signed out";
/// A launch no terminal started can only use the host's sign-in: say so, and name
/// the step that carries one.
pub(super) fn without_terminal(error: SeError, no_terminal: bool) -> SeError {
    match error.body.detail() {
        se_types::Detail::LaunchFailed(detail) if no_terminal && detail.reason == SIGNED_OUT => {
            SeError::new(se_types::Detail::LaunchFailed(se_types::details::LaunchFailed {
                subject: "Claude Code".into(),
                reason: "Claude Code reported the StateEngine host's own sign-in as signed out (it may be missing, expired or revoked), and no terminal launched this agent".into(),
                next_step: "Run se launch <agent> from a terminal with CLAUDE_CODE_OAUTH_TOKEN (for example from claude setup-token) or ANTHROPIC_API_KEY set".into(),
            }))
        }
        _ => error,
    }
}
fn authentication_status(bytes: &[u8], code: Option<i32>) -> Result<()> {
    #[derive(serde::Deserialize)]
    struct Status {
        #[serde(rename = "loggedIn")]
        logged_in: bool,
    }
    let status: Status = serde_json::from_slice(bytes).map_err(|_| {
        se_core::scope::unreadable(
            "Claude authentication status",
            "claude auth status --json did not return a readable loggedIn flag",
        )
    })?;
    match (status.logged_in, code) {
        (true, Some(0)) => Ok(()),
        (false, Some(0 | 1)) => Err(SeError::new(se_types::Detail::LaunchFailed(
            se_types::details::LaunchFailed {
                subject: "Claude Code".into(),
                reason: SIGNED_OUT.into(),
                next_step: "Sign in to Claude Code with: claude auth login".into(),
            },
        ))),
        _ => Err(se_core::scope::unreadable(
            "Claude authentication status",
            "claude auth status --json did not finish with a supported authentication result",
        )),
    }
}

async fn probe_output(
    command: &Path,
    arguments: &[&str],
    environment: Option<&[(OsString, OsString)]>,
    timeout: Duration,
    subject: &str,
) -> Result<Output> {
    use tokio::io::AsyncReadExt;
    if timeout.is_zero() {
        return Err(SeError::invalid(subject, "an unexpired probe deadline"));
    }
    let until = tokio::time::Instant::now() + timeout;
    let run_until = until - (timeout / 10).min(Duration::from_millis(500));
    let mut process = tokio::process::Command::from(se_proc::background_command(command));
    if let Some(environment) = environment {
        process.env_clear().envs(environment.iter().cloned());
    }
    let mut child = crate::child_io::spawn(
        process
            .args(arguments)
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true),
        crate::child_io::Pipes {
            stdin: false,
            stdout: true,
            stderr: false,
        },
    )
    .await
    .map_err(|e| se_core::scope::unreadable(subject, &e.to_string()))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| SeError::invalid(subject, "the retained output pipe"))?
        .take(65537);
    let mut bytes = Vec::new();
    let result = tokio::time::timeout_at(run_until, async {
        stdout
            .read_to_end(&mut bytes)
            .await
            .map_err(|e| se_core::scope::unreadable(subject, &e.to_string()))?;
        if bytes.len() > 65536 {
            return Err(SeError::invalid(subject, "output within 64 KiB"));
        }
        child
            .wait()
            .await
            .map_err(|e| se_core::scope::unreadable(subject, &e.to_string()))
    })
    .await;
    let status = match result {
        Ok(Ok(status)) => status,
        failed => {
            let _ = child.start_kill();
            if !matches!(
                tokio::time::timeout_at(until, child.wait()).await,
                Ok(Ok(_))
            ) {
                return Err(SeError::invalid(
                    subject,
                    "the exact probe child's witnessed exit before retrying",
                ));
            }
            return Err(match failed {
                Ok(Err(error)) => error,
                _ => SeError::invalid(subject, "an answer within the probe timeout"),
            });
        }
    };
    Ok(Output {
        status,
        stdout: bytes,
        stderr: Vec::new(),
    })
}

pub(super) fn parse_version(text: &str) -> Option<(u16, u16, u16)> {
    let mut parts = text.split('.').map(|part| part.parse::<u16>().ok());
    Some((parts.next()??, parts.next()??, parts.next()??))
}

pub(super) fn poisoned() -> SeError {
    SeError::invalid(
        "Claude harness",
        "an unpoisoned probe cache; restart the host",
    )
}

#[cfg(test)]
mod auth_tests {
    use super::authentication_status;
    use se_types::{Class, Detail};

    #[test]
    fn signed_out_is_a_refusal_with_the_provider_login_command() {
        for code in [0, 1] {
            let Err(error) =
                authentication_status(br#"{"loggedIn":false,"authMethod":"none"}"#, Some(code))
            else {
                panic!("signed-out status was accepted");
            };
            assert_eq!(error.body.code().class(), Class::Refused);
            let Detail::LaunchFailed(detail) = error.body.detail() else {
                panic!("not a launch refusal");
            };
            assert_eq!(
                detail.next_step,
                "Sign in to Claude Code with: claude auth login"
            );
            assert_eq!(error.body.code().class().exit_code(), 1);
        }
    }

    #[test]
    fn signed_in_accounts_and_api_keys_are_accepted() {
        for method in ["claude.ai", "api_key"] {
            let text = format!(r#"{{"loggedIn":true,"authMethod":"{method}"}}"#);
            assert!(authentication_status(text.as_bytes(), Some(0)).is_ok());
        }
    }

    #[test]
    fn unreadable_or_unsuccessful_status_is_never_assumed_signed_out() {
        for (bytes, code) in [
            (&b"not JSON"[..], Some(1)),
            (&br#"{}"#[..], Some(0)),
            (&br#"{"loggedIn":"false"}"#[..], Some(1)),
            (&br#"{"loggedIn":true}"#[..], Some(1)),
            (&br#"{"loggedIn":false}"#[..], Some(2)),
            (&br#"{"loggedIn":false}"#[..], None),
        ] {
            let Err(error) = authentication_status(bytes, code) else {
                panic!("unreadable status was accepted");
            };
            assert_eq!(error.body.code().class(), Class::Unreadable);
        }
    }
}
