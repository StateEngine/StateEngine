//! Thin adapter bridging `se`'s presentation and dispatch to `se_remote_cli::client`.
use crate::bootstrap::Bootstrap;
use se_core::ops::{AnyOp, AnyOutput};
use se_types::{ErrorEnvelope, RenderCx, Result, SeError};
use std::io::{self, Write};

struct Host;

impl se_remote_cli::client::ClientPresentation for Host {
    fn escape_far_text(&self, envelope: ErrorEnvelope) -> ErrorEnvelope {
        crate::render::error::escape_far_text(envelope)
    }

    fn write_error<O: Write, E: Write>(
        &self,
        error: &SeError,
        context: &RenderCx<'_>,
        json: bool,
        stdout: &mut O,
        stderr: &mut E,
    ) -> io::Result<u8> {
        crate::render::error::write(error, context, json, stdout, stderr)
    }

    fn write_output<O: Write>(
        &self,
        value: &AnyOutput,
        json: bool,
        quiet: bool,
        stdout: &mut O,
    ) -> io::Result<u8> {
        crate::render::output(value, json, quiet, stdout)
    }
}

pub(crate) fn pending_native(
    cx: &Bootstrap,
    input: &se_core::ops::MessageSend,
    json: bool,
    out: &mut impl Write,
) -> io::Result<()> {
    se_remote_cli::client::pending_native(cx.project.as_deref(), input, json, out)
}

pub(crate) fn parse_refusal(
    error: &SeError,
    json: bool,
    key: Option<&se_types::IdempotencyKey>,
    stderr: &mut impl Write,
) -> io::Result<u8> {
    se_remote_cli::client::parse_refusal(&Host, error, json, key, stderr)
}

pub(crate) fn refusal(
    error: &SeError,
    operation: &AnyOp,
    json: bool,
    stderr: &mut impl Write,
) -> io::Result<u8> {
    se_remote_cli::client::refusal(&Host, error, operation, json, stderr)
}

type Dispatch<'a> =
    dyn FnMut(&Bootstrap, AnyOp, &mut dyn FnMut(&str) -> io::Result<()>) -> Result<AnyOutput> + 'a;

pub(crate) fn run(
    cx: &Bootstrap,
    operation: AnyOp,
    json: bool,
    quiet: bool,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
    dispatch: &mut Dispatch<'_>,
) -> io::Result<u8> {
    let mut call = |op: AnyOp, diagnostic: &mut dyn FnMut(&str) -> io::Result<()>| {
        dispatch(cx, op, diagnostic)
    };
    se_remote_cli::client::run(&Host, operation, json, quiet, stdout, stderr, &mut call)
}
