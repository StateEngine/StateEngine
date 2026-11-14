//! Bounded local SSH diagnostics become actionable transport refusals.
use super::channel::unavailable;
use se_types::{Detail, Result, SeError, details};
use std::time::Duration;
use tokio::{io::AsyncReadExt, process::ChildStderr, sync::watch, task::JoinHandle};

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

#[derive(Clone, Copy, Default)]
struct Observation {
    forwarding_refused: bool,
    ended: bool,
}

pub(super) struct Diagnostics {
    observation: watch::Receiver<Observation>,
    task: Option<JoinHandle<std::io::Result<()>>>,
}

impl Diagnostics {
    pub(super) fn start(mut stderr: ChildStderr) -> Self {
        let (sender, observation) = watch::channel(Observation::default());
        let task = tokio::spawn(async move {
            // Preserve only a short overlap for a refusal split across reads.
            // Arbitrarily long or unterminated stderr cannot fill a pipe or
            // allocate unbounded memory, and private text never enters errors.
            let mut overlap = Vec::new();
            let mut block = [0; 1024];
            let mut seen = Observation::default();
            loop {
                let read = stderr.read(&mut block).await;
                let count = match read {
                    Ok(0) | Err(_) => {
                        seen.ended = true;
                        sender.send_replace(seen);
                        return read.map(|_| ());
                    }
                    Ok(count) => count,
                };
                overlap.extend_from_slice(&block[..count]);
                if overlap
                    .windows(b"administratively prohibited".len())
                    .any(|value| value == b"administratively prohibited")
                {
                    seen.forwarding_refused = true;
                    sender.send_replace(seen);
                }
                let discard = overlap.len().saturating_sub(64);
                overlap.drain(..discard);
            }
        });
        Self {
            observation,
            task: Some(task),
        }
    }

    pub(super) async fn forwarding_refusal(&mut self, port: u16) -> Option<SeError> {
        // SSH writes the refusal before closing the forwarded socket. Allow its
        // reader to catch up only on a failed transport, never on the happy path.
        let wait = async {
            loop {
                let seen = *self.observation.borrow_and_update();
                if seen.forwarding_refused || seen.ended {
                    return seen.forwarding_refused;
                }
                if self.observation.changed().await.is_err() {
                    return false;
                }
            }
        };
        if !tokio::time::timeout(Duration::from_millis(100), wait)
            .await
            .unwrap_or(false)
        {
            return None;
        }
        Some(SeError::new(se_types::Detail::ListenerUnavailable(
            se_types::details::ListenerUnavailable {
                subject: "SSH local TCP forwarding".into(),
                reason:
                    "The SSH server refused the forwarded connection: administratively prohibited."
                        .into(),
                next_step: format!(
                    "Ask the SSH server owner to allow local forwarding (AllowTcpForwarding local and DisableForwarding no), remove no-port-forwarding or enable port-forwarding on a restricted authorized key, and let PermitOpen/permitopen allow 127.0.0.1:{port}; then retry se remote add."
                ),
            },
        )))
    }

    pub(super) async fn close(&mut self) -> Result<()> {
        if let Some(task) = &mut self.task {
            // Keep the handle in self while awaiting: cancellation must leave
            // Drop able to abort the reader rather than detach it.
            let result = match tokio::time::timeout(Duration::from_secs(1), &mut *task).await {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(_)) => Err(unavailable("owned SSH diagnostic reader failed to join")),
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    Ok(())
                }
            };
            self.task = None;
            return result;
        }
        Ok(())
    }
}

impl Drop for Diagnostics {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
