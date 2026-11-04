use se_types::{ErrorEnvelope, RenderCx, SeError};
use std::io::{self, Write};

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
    let mut remedy = body.remedy(context).map_err(io::Error::other)?;
    let literal_recovery = error.code() == se_types::Code::AgentNameConflict
        || (error.code() == se_types::Code::TargetUnknown
            && matches!(remedy.command, Some(se_types::Cmd::Se { .. })))
        || matches!(error.body.detail(), se_types::Detail::UsageMissingArgument(detail)
            if detail.command == "se resume" && detail.argument == "--preview AGENT");
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
    let diagnostic = writeln!(
        stderr,
        "error[{}]: {}",
        error.code().as_str(),
        error.body.message()
    )
    .and_then(|()| writeln!(stderr, "  fix: {}", remedy.text))
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
