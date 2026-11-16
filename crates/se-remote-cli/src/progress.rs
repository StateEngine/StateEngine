//! Setup observations stay on stderr; stdout remains the final typed result.
use se_host::remote::ssh::{ImageProgress, ImageStage};
use se_types::{Result, SeError};
use std::io::Write;

pub(super) fn write(event: ImageProgress, json: bool, output: &mut dyn Write) -> Result<()> {
    let result = (|| -> std::io::Result<()> {
        if json {
            serde_json::to_writer(
                &mut *output,
                &serde_json::json!({
                    "schema":"stateengine.remote-setup-progress/v1",
                    "stage":event.stage,
                    "bytes_streamed":event.bytes_streamed,
                    "total_bytes":event.total_bytes,
                    "elapsed_ms":event.elapsed_ms,
                }),
            )
            .map_err(std::io::Error::other)?;
            writeln!(output)?;
        } else {
            match event.stage {
                ImageStage::Discovering => writeln!(output, "Preparing the remote runtime image…")?,
                ImageStage::Cached => {
                    writeln!(output, "Using the verified remote runtime image; pairing…")?
                }
                ImageStage::Uploading => {
                    let elapsed = event.elapsed_ms as f64 / 1000.0;
                    match (event.bytes_streamed, event.total_bytes) {
                        (Some(bytes), Some(total)) => writeln!(
                            output,
                            "Uploading runtime: {bytes} / {total} bytes ({elapsed:.1} seconds elapsed)"
                        )?,
                        (Some(bytes), None) => writeln!(
                            output,
                            "Uploading runtime: {bytes} bytes ({elapsed:.1} seconds elapsed)"
                        )?,
                        (None, _) => {
                            writeln!(output, "Uploading runtime ({elapsed:.1} seconds elapsed)…")?
                        }
                    }
                }
                ImageStage::Verifying => writeln!(output, "Verifying the uploaded runtime image…")?,
                ImageStage::Ready => writeln!(output, "Runtime image verified; pairing…")?,
            }
        }
        output.flush()
    })();
    result.map_err(|_| SeError::invalid("remote setup progress", "a writable stderr stream"))
}
