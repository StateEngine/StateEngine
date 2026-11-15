//! Fixed commands and image uploads retain and join each owned client.
use super::*;
use crate::remote::ssh_diagnostic::read_errors;
use se_types::SeError;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(in crate::remote) async fn ssh(destination: &str, command: String) -> Result<(bool, Vec<u8>)> {
    validate_destination(destination)?;
    let mut child = Command::new("ssh")
        .args(["-T", "-o", "BatchMode=yes", destination, &command])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| unavailable("cannot start the system SSH file-transfer client"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| unavailable("SSH output pipe absent"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| unavailable("SSH error pipe absent"))?;
    let result = timeout(Duration::from_secs(25), async {
        let mut bytes = Vec::new();
        let mut stdout = stdout.take(65537);
        tokio::try_join!(
            async {
                stdout
                    .read_to_end(&mut bytes)
                    .await
                    .map_err(|_| unavailable("SSH output could not be read"))
            },
            read_errors(destination, stderr)
        )?;
        if bytes.len() > 65536 {
            return Err(unavailable(
                "SSH output exceeded its bounded bootstrap response",
            ));
        }
        let status = child
            .wait()
            .await
            .map_err(|_| unavailable("SSH completion could not be observed"))?;
        Ok((status.success(), bytes))
    })
    .await;
    match result {
        Ok(Ok(value)) => Ok(value),
        other => {
            close(&mut child).await?;
            match other {
                Ok(Err(error)) => Err(error),
                _ => Err(unavailable("SSH bootstrap exceeded 25 seconds")),
            }
        }
    }
}

pub(super) fn verification_error(bytes: &[u8]) -> SeError {
    if let Some(mode) = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| {
            text.lines()
                .find_map(|line| line.strip_prefix("unsafe-mode:"))
        })
        .and_then(|mode| u16::from_str_radix(mode, 8).ok())
        .filter(|mode| *mode <= 0o7777)
    {
        return unavailable(&format!(
            "native runtime image mode {mode:04o} permits group or other writes; preserve the existing image and restore an account-owned image without foreign write permissions"
        ));
    }
    unavailable(
        "native runtime image verification failed; preserve the existing image and check its account ownership, permissions and distribution hash",
    )
}

pub(super) async fn send_image(
    destination: &str,
    image: &super::image::Image,
    upload: &str,
    cancelled: &AtomicBool,
    progress: &mut dyn FnMut(ImageProgress) -> Result<()>,
) -> Result<()> {
    let batch = super::sftp::upload_batch(&image.path, upload)?;
    let (sftp, ssh) = super::sftp::clients()?;
    let mut child = Command::new(sftp)
        .args(["-b", "-", "-o", "BatchMode=yes", "-S"])
        .arg(ssh)
        .arg(destination)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| {
            unavailable(
                "cannot start the system SFTP client; install the OpenSSH client tools and retry",
            )
        })?;
    let mut input = child
        .stdin
        .take()
        .ok_or_else(|| unavailable("SFTP image input pipe absent"))?;
    let output = child
        .stdout
        .take()
        .ok_or_else(|| unavailable("SFTP image output pipe absent"))?;
    let errors = child
        .stderr
        .take()
        .ok_or_else(|| unavailable("SFTP image error pipe absent"))?;
    let expected = image.expected;
    let started = std::time::Instant::now();
    let result = {
        let transfer = async {
            tokio::try_join!(
                async {
                    input
                        .write_all(batch.as_bytes())
                        .await
                        .map_err(|_| unavailable("SFTP upload command could not be written"))?;
                    input
                        .shutdown()
                        .await
                        .map_err(|_| unavailable("SFTP command input could not be closed"))?;
                    drop(input);
                    Ok(())
                },
                drain(output, 65536),
                read_errors(destination, errors)
            )?;
            if !child
                .wait()
                .await
                .map_err(|_| unavailable("SFTP image completion unreadable"))?
                .success()
            {
                return Err(unavailable(
                    "SFTP image stream failed; the image was not published",
                ));
            }
            Ok(())
        };
        tokio::pin!(transfer);
        let mut ticks = tokio::time::interval(Duration::from_secs(1));
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let limit = tokio::time::sleep(Duration::from_secs(600));
        tokio::pin!(limit);
        loop {
            tokio::select! {
                biased;
                result = &mut transfer => break result,
                _ = &mut limit => break Err(unavailable("remote image transfer exceeded ten minutes; its upload was not published")),
                _ = ticks.tick() => {
                    if cancelled.load(Ordering::Acquire) {
                        break Err(unavailable("remote image transfer was cancelled; its upload was not published"));
                    }
                    if let Err(error) = progress(ImageProgress {
                        stage: ImageStage::Uploading,
                        // Batch SFTP has no intermediate byte-progress receipt.
                        bytes_streamed: None,
                        total_bytes: Some(expected),
                        elapsed_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                    }) { break Err(error); }
                }
            }
        }
    };
    if result.is_err() {
        close(&mut child).await?;
    }
    result
}

async fn drain(reader: impl tokio::io::AsyncRead + Unpin, limit: usize) -> Result<()> {
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| unavailable("SFTP image response unreadable"))?;
    if bytes.len() > limit {
        return Err(unavailable("SFTP image response exceeded its bound"));
    }
    Ok(())
}

/// A failed command retains custody until this specific native child is joined.
pub(super) async fn close(child: &mut Child) -> Result<()> {
    if child
        .try_wait()
        .map_err(|_| unavailable("owned SSH process custody is unreadable"))?
        .is_none()
    {
        child
            .start_kill()
            .map_err(|_| unavailable("cannot stop the owned SSH process"))?;
    }
    child
        .wait()
        .await
        .map_err(|_| unavailable("cannot join the owned SSH process"))?;
    Ok(())
}
