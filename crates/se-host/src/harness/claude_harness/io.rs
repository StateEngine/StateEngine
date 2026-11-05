//! Provider framing, output drains and bounded executable probes.
use super::{Binding, READ_CHUNK, claude};
use crate::{CallContext, ProviderStream, StreamRead};
use se_types::{Body, Result, SeError};
use std::{
    ffi::OsString,
    path::Path,
    process::Output,
    sync::Arc,
    time::{Duration, Instant},
};

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

pub(super) fn version_output(command: &Path, timeout: Duration) -> Result<String> {
    let output = probe_output(
        command,
        &["--version"],
        None,
        timeout,
        "Claude version probe",
    )?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub(super) fn authentication(
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
    )?;
    authentication_status(&output.stdout, output.status.code())
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
        (false, Some(0 | 1)) => Err(SeError::new(se_types::Detail::SetupRequired(
            se_types::details::SetupRequired {
                subject: "Claude Code".into(),
                reason: "you are signed out".into(),
                next_step: "Sign in to Claude Code with: claude auth login".into(),
            },
        ))),
        _ => Err(se_core::scope::unreadable(
            "Claude authentication status",
            "claude auth status --json did not finish with a supported authentication result",
        )),
    }
}

fn probe_output(
    command: &Path,
    arguments: &[&str],
    environment: Option<&[(OsString, OsString)]>,
    timeout: Duration,
    subject: &str,
) -> Result<Output> {
    let mut process = std::process::Command::new(command);
    if let Some(environment) = environment {
        process.env_clear().envs(environment.iter().cloned());
    }
    let mut child = process
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| {
            se_core::scope::unreadable("Claude executable", &e.to_string()).with_cause(e)
        })?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                // Our own direct child, reaped below; never a name-matched kill.
                let _ = child.kill();
                let _ = child.wait();
                return Err(SeError::invalid(
                    subject,
                    "an answer within the probe timeout",
                ));
            }
            Err(e) => {
                return Err(se_core::scope::unreadable(subject, &e.to_string()));
            }
        }
    }
    child
        .wait_with_output()
        .map_err(|e| se_core::scope::unreadable(subject, &e.to_string()))
}

#[cfg(test)]
mod auth_tests {
    use super::authentication_status;
    use se_types::{Class, Detail};

    #[test]
    fn signed_out_is_a_refusal_with_the_provider_login_command() {
        for code in [0, 1] {
            let error =
                authentication_status(br#"{"loggedIn":false,"authMethod":"none"}"#, Some(code))
                    .expect_err("signed out");
            assert_eq!(error.body.code().class(), Class::Refused);
            let Detail::SetupRequired(detail) = error.body.detail() else {
                panic!("not a setup refusal");
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
            let error = authentication_status(bytes, code).expect_err("unreadable status");
            assert_eq!(error.body.code().class(), Class::Unreadable);
        }
    }
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
