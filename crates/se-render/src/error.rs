use se_types::{ErrorEnvelope, RenderCx, SeError};
use std::io::{self, Write};

/// Terminal text of a far body is peer-supplied: escape it once here,
/// before it can reach a terminal or a log. Local bodies pass through
/// unchanged.
pub fn escape_far_text(envelope: ErrorEnvelope) -> ErrorEnvelope {
    if !envelope.body().far() {
        return envelope;
    }
    let message = envelope.message().escape_debug().to_string();
    let remedy_text = envelope.remedy().text.escape_debug().to_string();
    envelope.with_terminal_text(message, remedy_text)
}
/// Error diagnostics remain on stderr even when the caller requests JSON.
/// Neither an internal source chain nor credential material is rendered.
pub fn write(
    error: &SeError,
    context: &RenderCx<'_>,
    json: bool,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> io::Result<u8> {
    let mut body = error.body.clone();
    // Startup recovery already preserves the full original argv and resolved
    // selectors. Setup's home injection must not rewrite that literal retry.
    let mut remedy = if error.code() == se_types::Code::RuntimeStartPending {
        body.remedy(&RenderCx::default())
    } else {
        body.remedy(context)
    }
    .map_err(io::Error::other)?;
    // A peer-supplied body must not gain local literal remedies: its text is
    // shown escaped and never re-resolved into instructions.
    let far = error.body.far();
    let literal_recovery = !far
        && (matches!(
            error.code(),
            se_types::Code::AgentNameConflict | se_types::Code::RuntimeStartPending
        ) || (error.code() == se_types::Code::TargetUnknown
            && matches!(remedy.command, Some(se_types::Cmd::Se { .. })))
            || matches!(error.body.detail(), se_types::Detail::UsageMissingArgument(detail)
                if detail.command == "se resume" && detail.argument == "--preview AGENT")
            || matches!(error.body.detail(), se_types::Detail::UsageInvalidValue(detail)
                if detail.argument == "se resume AGENT"));
    if literal_recovery {
        if let Some(se_types::Cmd::Se { argv }) = &remedy.command {
            if let Some(command) = se_core::ops::AgentCommand::from_argv(argv.as_slice().to_vec()) {
                remedy.text = format!(
                    "{} {}: {}",
                    remedy.text,
                    se_core::ops::AgentCommand::instruction("Run"),
                    command.command
                );
            } else {
                remedy.text.push_str(" The data home contains a line break; use the literal remedy.command.argv instead of pasting it into a shell.");
            }
        }
        body = body.with_remedy(remedy.clone());
    }
    // The literal remedy already contains the resolved home. Do not resolve
    // that literal command a second time while building the JSON envelope.
    let envelope = if literal_recovery {
        ErrorEnvelope::new(body, &RenderCx::default())
    } else {
        ErrorEnvelope::new(body, context)
    }
    .map_err(io::Error::other)?;
    let envelope = escape_far_text(envelope);
    if !json
        && !far
        && matches!(error.body.detail(), se_types::Detail::UsageInvalidValue(detail)
            if detail.argument == "se resume AGENT")
        && let Some(se_types::Cmd::Se { argv }) = &remedy.command
        && let Some(command) = se_core::ops::AgentCommand::from_argv(argv.as_slice().to_vec())
    {
        writeln!(
            stderr,
            "error[{}]: Resume with: {}",
            error.code().as_str(),
            command.command
        )?;
        stderr.flush()?;
        return Ok(error.class().exit_code());
    }
    // Remote peer text is not ours: escape it once here, before it can
    // reach a terminal or a log. Local bodies keep their literal text.
    let message = if far {
        error.body.message().escape_debug().to_string()
    } else {
        error.body.message()
    };
    let remedy_text = if far {
        remedy.text.escape_debug().to_string()
    } else {
        remedy.text.clone()
    };
    let diagnostic = writeln!(
        stderr,
        "{}[{}]: {}",
        if error.code() == se_types::Code::RuntimeStartPending {
            "incomplete"
        } else {
            "error"
        },
        error.code().as_str(),
        message
    )
    .and_then(|()| writeln!(stderr, "  fix: {}", remedy_text))
    .and_then(|()| stderr.flush());
    // Attempt the structured result even if stderr is unavailable.
    if json {
        serde_json::to_writer(&mut *stdout, &envelope).map_err(io::Error::other)?;
        writeln!(stdout)?;
        stdout.flush()?;
    }
    diagnostic?;
    Ok(error.class().exit_code())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(reason: &str, next_step: &str) -> SeError {
        SeError::from(
            se_types::ErrorBody::new(se_types::Detail::ListenerUnavailable(
                se_types::details::ListenerUnavailable {
                    subject: "the socket".into(),
                    reason: reason.into(),
                    next_step: next_step.into(),
                },
            ))
            .with_far_origin(),
        )
    }

    #[test]
    fn far_plain_text_is_escaped() -> io::Result<()> {
        let error = listener("peer says \u{1b}[31mbad", "reconnect \u{1b}[1mnow");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = write(
            &error,
            &RenderCx::default(),
            false,
            &mut stdout,
            &mut stderr,
        )?;
        assert_eq!(code, 1);
        let text = String::from_utf8(stderr).map_err(io::Error::other)?;
        assert!(!text.contains('\u{1b}'), "raw escape byte in {text:?}");
        assert!(
            text.contains(
                "error[listener-unavailable]: Listener the socket: peer says \\u{1b}[31mbad"
            ),
            "{text:?}"
        );
        assert!(text.contains("  fix: reconnect \\u{1b}[1mnow"), "{text:?}");
        Ok(())
    }

    #[test]
    fn far_json_terminal_text_is_escaped_but_data_is_raw() -> io::Result<()> {
        let error = listener("peer says \u{1b}[31mbad", "reconnect \u{1b}[1mnow");
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = write(&error, &RenderCx::default(), true, &mut stdout, &mut stderr)?;
        assert_eq!(code, 1);
        let value: serde_json::Value =
            serde_json::from_str(&String::from_utf8(stdout).map_err(io::Error::other)?)
                .map_err(io::Error::other)?;
        assert_eq!(
            value["message"],
            "Listener the socket: peer says \\u{1b}[31mbad"
        );
        assert_eq!(value["remedy"]["text"], "reconnect \\u{1b}[1mnow");
        assert_eq!(value["far"], true);
        // The typed body keeps the peer's bytes; only terminal text is escaped.
        assert_eq!(value["detail"]["reason"], "peer says \u{1b}[31mbad");
        Ok(())
    }

    #[test]
    fn local_text_keeps_its_bytes() -> io::Result<()> {
        let error = SeError::from(se_types::ErrorBody::new(
            se_types::Detail::ListenerUnavailable(se_types::details::ListenerUnavailable {
                subject: "the socket".into(),
                reason: "local says \u{1b}[31mbad".into(),
                next_step: "reconnect \u{1b}[1mnow".into(),
            }),
        ));
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        write(
            &error,
            &RenderCx::default(),
            false,
            &mut stdout,
            &mut stderr,
        )?;
        let text = String::from_utf8(stderr).map_err(io::Error::other)?;
        assert!(
            text.contains('\u{1b}'),
            "local text must not be escaped: {text:?}"
        );
        Ok(())
    }
}
