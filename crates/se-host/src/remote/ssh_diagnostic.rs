//! Bounded local SSH diagnostics become actionable transport refusals.
use super::channel::unavailable;
use se_types::error::{Detail, details};
use se_types::{Result, SeError};
use tokio::io::AsyncReadExt;

pub(super) async fn read_errors(
    destination: &str,
    reader: impl tokio::io::AsyncRead + Unpin,
) -> Result<()> {
    let mut reader = reader.take(4097);
    let mut bytes = Vec::new();
    loop {
        let count = reader
            .read_buf(&mut bytes)
            .await
            .map_err(|_| unavailable("SSH output could not be read"))?;
        if bytes.len() > 4096 {
            return Err(unavailable(
                "SSH output exceeded its bounded bootstrap response",
            ));
        }
        // A terminal local SSH diagnostic is already a refusal. Do not wait
        // for pipe EOF or try a different remote operating system afterward.
        if bytes
            .split(|byte| *byte == b'\n')
            .any(|line| line.starts_with(b"ssh: Could not resolve hostname "))
        {
            return Err(SeError::new(Detail::ListenerUnavailable(details::ListenerUnavailable {
                subject: format!("SSH destination {destination}"),
                reason: format!("SSH could not resolve the host name for {destination}"),
                next_step: "Check the host name or define the destination alias in your SSH configuration, then retry.".into(),
            })));
        }
        if count == 0 {
            return Ok(());
        }
    }
}
