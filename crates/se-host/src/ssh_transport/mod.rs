//! Owned system OpenSSH commands, file transfers and bounded diagnostics.
//! Pairing, image verification and publication remain with their callers.
use se_remote::{channel::unavailable, ssh::validate_destination};
use se_types::Result;
use std::{process::Stdio, time::Duration};
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
    time::timeout,
};
mod diagnostics;
mod sftp;
mod transfer;
pub(crate) use diagnostics::Diagnostics;
use diagnostics::read_errors;
pub(crate) use transfer::upload;

pub(crate) async fn command(destination: &str, command: String) -> Result<(bool, Vec<u8>)> {
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

/// A failed command retains custody until this specific native child is joined.
pub(crate) async fn close(child: &mut Child) -> Result<()> {
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
