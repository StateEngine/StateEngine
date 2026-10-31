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
    let envelope = ErrorEnvelope::new(error.body.clone(), context).map_err(io::Error::other)?;
    let remedy = error.body.remedy(context).map_err(io::Error::other)?;
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
