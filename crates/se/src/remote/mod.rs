//! CLI consumer for the same admitted source-host broker used by named MCP.
//! stdout is final typed output/NDJSON; pending and errors have bounded stderr
//! records. No private key, socket runtime or helper is initialized here.
use crate::bootstrap::Bootstrap;
use se_core::ops::{AnyOp, AnyOutput, remote::*};
use se_types::{Result, SeError};
use serde::Serialize;
use std::io::{self, Write};
type Dispatch<'a> =
    dyn FnMut(&Bootstrap, AnyOp, &mut dyn FnMut(&str) -> io::Result<()>) -> Result<AnyOutput> + 'a;
#[derive(Serialize)]
struct SendStatus<'a> {
    schema: &'static str,
    status: &'static str,
    #[serde(flatten)]
    binding: &'a RemoteSendPreparation,
}
fn pending(p: &RemoteSendPreparation, json: bool, out: &mut impl Write) -> io::Result<()> {
    if json {
        serde_json::to_writer(
            &mut *out,
            &SendStatus {
                schema: "stateengine.remote-send-status/v1",
                status: "local_pending",
                binding: p,
            },
        )
        .map_err(io::Error::other)?;
        writeln!(out)?;
    } else {
        writeln!(
            out,
            "Pending remote send {} to {}/{} session {} (host {:?}, grant {}); no durable receipt yet",
            p.idempotency_key, p.target.project, p.target.agent, p.session, p.host, p.grant
        )?;
    }
    out.flush()
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
            pending(&p, json, stderr)?;
            match dispatch(cx, AnyOp::RemoteSend(input), &mut diagnostic) {
                Ok(AnyOutput::RemoteSend(v)) => {
                    if let se_types::Receipt::Refused { error: body } = &v.value.receipt {
                        return error(&SeError::from((**body).clone()), json, Some(&p), stderr);
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
        AnyOp::RemoteWatch(mut input) => loop {
            let follow = input.follow;
            let output = dispatch(cx, AnyOp::RemoteWatch(input.clone()), &mut diagnostic);
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
                    let code =
                        crate::render::output(&AnyOutput::RemoteWatch(v), json, quiet, stdout)?;
                    stdout.flush()?;
                    if !follow || input.wait_ms == 0 || reset {
                        return Ok(code);
                    }
                }
                Ok(_) => {
                    return error(
                        &SeError::invalid("remote watch", "the typed watch batch"),
                        json,
                        None,
                        stderr,
                    );
                }
                Err(e) => return error(&e, json, None, stderr),
            }
        },
        operation => match dispatch(cx, operation, &mut diagnostic) {
            Ok(output) => crate::render::output(&output, json, quiet, stdout),
            Err(e) => error(&e, json, None, stderr),
        },
    }
}
