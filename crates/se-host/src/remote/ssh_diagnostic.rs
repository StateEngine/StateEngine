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

#[cfg(all(test, target_os = "linux"))]
mod review_399_diagnostic {
    #[test]
    fn review_399_read_errors_controls() {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let cases: Vec<(&str, Vec<u8>, Option<&str>)> = vec![
            ("permission", b"warning\nREVIEW_DENIED publickey\r\n\n".to_vec(), Some("REVIEW_DENIED publickey")),
            ("hostile", b"\x1b]0;title\x07\x1b[31mREVIEW_DENIED\x1b[0m\x00\x7f\xff\r\n".to_vec(), Some("REVIEW_DENIED")),
            ("long", [vec![b'x'; 500], b"REVIEW_DENIED".to_vec()].concat(), Some("REVIEW_DENIED")),
            ("empty", b"\n\r\n\xff".to_vec(), Some("")),
            ("bound", vec![b'x'; 4097], None),
        ];
        let mut failures = Vec::new();
        for (name, bytes, expected) in cases {
            let outcome = runtime.block_on(super::read_errors("review-destination", &bytes[..]));
            let (passed, observed) = match outcome {
                Ok(value) => {
                    let observed = serde_json::to_value(value).unwrap();
                    let passed = match (expected, observed.as_str()) {
                        (Some(needle), Some(text)) => text.contains(needle) && text.len() <= 160 && text.bytes().all(|b| b == b' ' || b.is_ascii_graphic()),
                        _ => false,
                    };
                    (passed, observed)
                }
                Err(error) => (expected.is_none() && error.body.message().contains("bounded bootstrap response"), serde_json::json!({"error":error.body.message()})),
            };
            println!("REVIEW399 {}", serde_json::json!({"case":name,"passed":passed,"observed":observed}));
            if !passed { failures.push(name); }
        }
        assert!(failures.is_empty(), "diagnostic cases failed: {failures:?}");
    }
}
