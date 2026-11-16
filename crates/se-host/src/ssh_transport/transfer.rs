//! SFTP owns transfer completion and elapsed-time heartbeats, never publication.
use super::{close, read_errors, unavailable};
use se_types::Result;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::Command,
};

pub(crate) async fn upload(
    destination: &str,
    path: &std::path::Path,
    upload: &str,
    cancelled: &AtomicBool,
    heartbeat: &mut dyn FnMut(Duration) -> Result<()>,
) -> Result<()> {
    let batch = super::sftp::upload_batch(path, upload)?;
    let (sftp, ssh) = super::sftp::clients()?;
    let mut child = crate::child_io::spawn(
        Command::new(sftp)
            .args(["-b", "-", "-o", "BatchMode=yes", "-S"])
            .arg(ssh)
            .arg(destination)
            .kill_on_drop(true),
        crate::child_io::Pipes {
            stdin: true,
            stdout: true,
            stderr: true,
        },
    )
    .await
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
                    if let Err(error) = heartbeat(started.elapsed()) { break Err(error); }
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
