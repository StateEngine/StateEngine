//! CLI consumer for the same admitted source-host broker used by named MCP.
//! stdout is final typed output/NDJSON; pending and errors have bounded stderr
//! records. No private key, socket runtime or helper is initialized here.
use crate::bootstrap::Bootstrap;
use se_core::ops::{AnyOp, AnyOutput, remote::*};
use se_types::{Result, SeError};
use serde::Serialize;
use std::io::{self, Write};
mod measure;
type Dispatch<'a> =
    dyn FnMut(&Bootstrap, AnyOp, &mut dyn FnMut(&str) -> io::Result<()>) -> Result<AnyOutput> + 'a;
#[derive(Serialize)]
struct SendStatus<'a, T> {
    schema: &'static str,
    status: &'static str,
    #[serde(flatten)]
    binding: &'a T,
}
fn send_status<T: Serialize>(
    schema: &'static str,
    status: &'static str,
    binding: &T,
    description: std::fmt::Arguments<'_>,
    json: bool,
    out: &mut impl Write,
) -> io::Result<()> {
    if json {
        serde_json::to_writer(
            &mut *out,
            &SendStatus {
                schema,
                status,
                binding,
            },
        )
        .map_err(io::Error::other)?;
        writeln!(out)?;
    } else {
        writeln!(out, "{description}; no durable receipt yet")?;
    }
    out.flush()
}
/// This is presentation only. Native mail retains its ordinary admission,
/// transaction, notification completion and final receipt/error renderer.
pub(crate) fn pending_native(
    cx: &Bootstrap,
    input: &se_core::ops::MessageSend,
    json: bool,
    out: &mut impl Write,
) -> io::Result<()> {
    let binding = serde_json::json!({
        "idempotency_key":input.idempotency_key,
        "project_selector":cx.project,"recipient_selector":input.to,
        "body_bytes":input.body.len(),
    });
    send_status(
        "stateengine.send-status/v1",
        "local_pending",
        &binding,
        format_args!("Pending send {} to {}", input.idempotency_key, input.to),
        json,
        out,
    )
}
fn error(
    error: &SeError,
    json: bool,
    key: Option<&RemoteSendPreparation>,
    original_key: Option<&se_types::IdempotencyKey>,
    out: &mut impl Write,
) -> io::Result<u8> {
    if json {
        let envelope =
            se_types::ErrorEnvelope::new(error.body.clone(), &se_types::RenderCx::default())
                .map_err(io::Error::other)?;
        let envelope = crate::render::error::escape_far_text(envelope);
        if key.is_none() && original_key.is_none() {
            serde_json::to_writer(&mut *out, &envelope).map_err(io::Error::other)?;
            writeln!(out)?;
            out.flush()?;
            return Ok(1);
        }
        let status = if matches!(error.class(), se_types::Class::Unknown) {
            "unknown_retryable"
        } else {
            "failed"
        };
        // No plain banners on structured stderr and no error copied to stdout.
        serde_json::to_writer(&mut *out,&serde_json::json!({"schema":"stateengine.remote-send-status/v1","status":status,"binding":key,"idempotency_key":original_key,"error":envelope})).map_err(io::Error::other)?;
        writeln!(out)?;
        out.flush()?;
        Ok(1)
    } else {
        if let Some(p) = key {
            writeln!(
                out,
                "Remote send {}: {}; retry an uncertain exchange with the same host, key, body, target and session",
                p.idempotency_key,
                if matches!(error.class(), se_types::Class::Unknown) {
                    "unknown"
                } else {
                    "failed"
                }
            )?;
        }
        crate::render::error::write(
            error,
            &se_types::RenderCx::default(),
            false,
            &mut io::sink(),
            out,
        )
        .map(|_| 1)
    }
}
pub(crate) fn parse_refusal(
    error: &SeError,
    json: bool,
    key: Option<&se_types::IdempotencyKey>,
    stderr: &mut impl Write,
) -> io::Result<u8> {
    self::error(error, json, None, key, stderr)
}

pub(crate) fn refusal(
    error: &SeError,
    operation: &AnyOp,
    json: bool,
    stderr: &mut impl Write,
) -> io::Result<u8> {
    self::error(error, json, None, operation.idempotency_key(), stderr)
}
pub(crate) fn run(
    cx: &Bootstrap,
    operation: AnyOp,
    json: bool,
    quiet: bool,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    dispatch: &mut Dispatch<'_>,
) -> io::Result<u8> {
    let original_key = operation.idempotency_key().cloned();
    let error = |e: &SeError, json, key, stderr: &mut _| {
        self::error(e, json, key, original_key.as_ref(), stderr)
    };
    let mut diagnostic = |_: &str| {
        Err(io::Error::other(
            "remote operations require typed status/errors, not progress banners",
        ))
    };
    match operation {
        AnyOp::RemoteSend(mut input) => {
            // Like native mail, echo the submitted request before host IPC.
            // These are selectors, not admitted host/grant facts or a receipt.
            let requested = serde_json::json!({
                "host_selector": input.host,
                "target": input.request.target,
                "session": input.request.session,
                "idempotency_key": input.request.idempotency_key,
                "body_bytes": input.request.body.len(),
            });
            send_status(
                "stateengine.remote-send-status/v1",
                "local_pending",
                &requested,
                format_args!(
                    "Pending remote send {} to {}/{} session {} via {}",
                    input.request.idempotency_key,
                    input.request.target.project,
                    input.request.target.agent,
                    input.request.session,
                    input.host,
                ),
                json,
                stderr,
            )?;
            let prepared = dispatch(
                cx,
                AnyOp::RemotePrepareSend(RemotePrepareSendCall {
                    host: input.host.clone(),
                    request: input.request.clone(),
                }),
                &mut diagnostic,
            );
            let p = match prepared {
                Ok(AnyOutput::RemotePrepareSend(p)) => p.value,
                Ok(_) => {
                    return error(
                        &SeError::invalid(
                            "remote preparation",
                            "the admitted nonsecret binding result",
                        ),
                        json,
                        None,
                        stderr,
                    );
                }
                Err(e) => return error(&e, json, None, stderr),
            };
            if p.idempotency_key != input.request.idempotency_key
                || p.target != input.request.target
                || p.session != input.request.session
                || p.body_bytes as usize != input.request.body.len()
            {
                return error(
                    &SeError::invalid("remote preparation", "the original keyed request"),
                    json,
                    None,
                    stderr,
                );
            }
            if input
                .expected_binding
                .as_ref()
                .is_some_and(|expected| expected.host != p.host || expected.grant != p.grant)
            {
                return error(
                    &SeError::invalid(
                        "remote binding",
                        "the original host/grant; do not retarget an uncertain send",
                    ),
                    json,
                    None,
                    stderr,
                );
            }
            input.expected_binding = Some(Box::new(RemoteBindingSelection {
                host: p.host,
                grant: p.grant.clone(),
            }));
            // Preserve the resolved retry binding before a mutation can cross
            // the wire, even if this process loses the eventual final reply.
            send_status(
                "stateengine.remote-send-status/v1",
                "binding_ready",
                &p,
                format_args!(
                    "Prepared remote send {} to {}/{} session {} (host {:?}, grant {})",
                    p.idempotency_key, p.target.project, p.target.agent, p.session, p.host, p.grant
                ),
                json,
                stderr,
            )?;
            match dispatch(cx, AnyOp::RemoteSend(input), &mut diagnostic) {
                Ok(AnyOutput::RemoteSend(v)) => {
                    if let se_types::Receipt::Refused { error: body } = &v.value.receipt {
                        return error(
                            &SeError::from((**body).clone().with_far_origin()),
                            json,
                            Some(&p),
                            stderr,
                        );
                    }
                    crate::render::output(&AnyOutput::RemoteSend(v), json, quiet, stdout)
                }
                Ok(_) => error(
                    &SeError::invalid("remote send", "the same typed final send result"),
                    json,
                    Some(&p),
                    stderr,
                ),
                Err(e) => error(&e, json, Some(&p), stderr),
            }
        }
        AnyOp::RemoteWatch(input) => watch(
            cx,
            (
                se_core::ops::ClientWatchCall {
                    request: input.request,
                    reader_id: input.reader_id,
                    wait_ms: input.wait_ms,
                    follow: input.follow,
                },
                Some(input.host),
            ),
            json,
            quiet,
            stdout,
            stderr,
            dispatch,
        ),
        AnyOp::ClientWatch(input) => {
            watch(cx, (input, None), json, quiet, stdout, stderr, dispatch)
        }
        operation => match dispatch(cx, operation, &mut diagnostic) {
            Ok(output) => crate::render::output(&output, json, quiet, stdout),
            Err(e) => error(&e, json, None, stderr),
        },
    }
}

fn watch(
    cx: &Bootstrap,
    selection: (se_core::ops::ClientWatchCall, Option<String>),
    json: bool,
    quiet: bool,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    dispatch: &mut Dispatch<'_>,
) -> io::Result<u8> {
    let (mut input, host) = selection;
    // Each terminal keeps its own bounded subscription, including when another
    // terminal has the same targets and cursors and is waiting on a long poll.
    input.reader_id = input.follow.then(|| *uuid::Uuid::new_v4().as_bytes());
    let mut diagnostic = |_: &str| {
        Err(io::Error::other(
            "client watch requires typed status/errors",
        ))
    };
    loop {
        let started = std::time::Instant::now();
        let follow = input.follow;
        let operation = match &host {
            Some(host) => AnyOp::RemoteWatch(RemoteWatchCall {
                host: host.clone(),
                request: input.request.clone(),
                reader_id: input.reader_id,
                wait_ms: input.wait_ms,
                follow: input.follow,
            }),
            None => AnyOp::ClientWatch(input.clone()),
        };
        let output = dispatch(cx, operation, &mut diagnostic);
        match output {
            Ok(AnyOutput::RemoteWatch(v)) => {
                let reset = v.value.reset_required;
                if reset {
                    input.request.cursors.clear();
                }
                for cursor in &v.value.cursors {
                    if let Some(saved) = input
                        .request
                        .cursors
                        .iter_mut()
                        .find(|saved| saved.target == cursor.target)
                    {
                        *saved = cursor.clone();
                    } else {
                        input.request.cursors.push(cursor.clone());
                    }
                }
                let measured = input.request.measure;
                let output = AnyOutput::RemoteWatch(v);
                let code = crate::render::output(&output, json, quiet, stdout)?;
                stdout.flush()?;
                if measured && let AnyOutput::RemoteWatch(v) = &output {
                    measure::flushed(&v.value, started, stderr)?;
                }
                if !follow || input.wait_ms == 0 || reset {
                    return Ok(code);
                }
            }
            Ok(_) => {
                return self::error(
                    &SeError::invalid("remote watch", "the typed watch batch"),
                    json,
                    None,
                    None,
                    stderr,
                );
            }
            Err(e) => return self::error(&e, json, None, None, stderr),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn far_error() -> SeError {
        SeError::from(
            se_types::ErrorBody::new(se_types::Detail::ListenerUnavailable(
                se_types::details::ListenerUnavailable {
                    subject: "the socket".into(),
                    reason: "peer says \u{1b}[31mbad".into(),
                    next_step: "reconnect \u{1b}[1mnow".into(),
                },
            ))
            .with_far_origin(),
        )
    }

    fn preparation() -> io::Result<RemoteSendPreparation> {
        Ok(RemoteSendPreparation {
            host: se_types::remote::RemoteHostId(se_types::Sha256::from_bytes([0; 32])),
            grant: "rgr_01920e00-7f00-7000-8000-000000000000"
                .parse()
                .map_err(io::Error::other)?,
            target: se_types::remote::RemoteTarget {
                project: "prj_01920e00-7f00-7000-8000-000000000000"
                    .parse()
                    .map_err(io::Error::other)?,
                agent: "ag_01920e00-7f00-7000-8000-000000000000"
                    .parse()
                    .map_err(io::Error::other)?,
            },
            session: "ses_01920e00-7f00-7000-8000-000000000000"
                .parse()
                .map_err(io::Error::other)?,
            idempotency_key: "test-idempotency-key".parse().map_err(io::Error::other)?,
            body_bytes: 1,
        })
    }

    #[test]
    fn far_error_shapes_escape_terminal_text() -> io::Result<()> {
        let far = far_error();
        let binding = preparation()?;

        // JSON without a binding: the bare escaped envelope.
        let mut out = Vec::new();
        assert_eq!(self::error(&far, true, None, None, &mut out)?, 1);
        let value: serde_json::Value =
            serde_json::from_str(&String::from_utf8(out).map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
        assert_eq!(
            value["message"],
            "Listener the socket: peer says \\u{1b}[31mbad"
        );
        assert_eq!(value["remedy"]["text"], "reconnect \\u{1b}[1mnow");
        assert_eq!(value["far"], true);

        // JSON with a binding: the send-status wrapper carries the same text.
        let mut out = Vec::new();
        assert_eq!(self::error(&far, true, Some(&binding), None, &mut out)?, 1);
        let value: serde_json::Value =
            serde_json::from_str(&String::from_utf8(out).map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
        assert_eq!(value["schema"], "stateengine.remote-send-status/v1");
        assert_eq!(
            value["error"]["message"],
            "Listener the socket: peer says \\u{1b}[31mbad"
        );

        // Plain without a binding: the escaped diagnostic line.
        let mut out = Vec::new();
        assert_eq!(self::error(&far, false, None, None, &mut out)?, 1);
        let text = String::from_utf8(out).map_err(io::Error::other)?;
        assert!(!text.contains('\u{1b}'), "raw escape byte in {text:?}");
        assert!(text.contains("peer says \\u{1b}[31mbad"), "{text:?}");

        // Plain with a binding: the banner plus the escaped diagnostic.
        let mut out = Vec::new();
        assert_eq!(self::error(&far, false, Some(&binding), None, &mut out)?, 1);
        let text = String::from_utf8(out).map_err(io::Error::other)?;
        assert!(!text.contains('\u{1b}'), "raw escape byte in {text:?}");
        assert!(
            text.contains(&format!("Remote send {}", binding.idempotency_key)),
            "{text:?}"
        );
        assert!(text.contains("  fix: reconnect \\u{1b}[1mnow"), "{text:?}");
        Ok(())
    }
}
