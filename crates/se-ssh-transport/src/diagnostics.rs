//! Bounded local SSH diagnostics become actionable transport refusals.
use super::unavailable;
use se_types::{Detail, Result, SeError, details};
use std::time::Duration;
use tokio::{io::AsyncReadExt, sync::watch, task::JoinHandle};

pub(super) async fn read_errors(
    destination: &str,
    reader: impl tokio::io::AsyncRead + Unpin,
) -> Result<String> {
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
            return Ok(sanitized_stderr_tail(&bytes));
        }
    }
}

/// Bounded, sanitized view of the local SSH client's stderr for a refusal:
/// the last non-empty line, printable ASCII only, length-capped. It is the
/// client's own verdict ("Permission denied (publickey).", "Connection
/// refused"), never a product claim; everything else in stderr is discarded.
pub(super) fn sanitized_stderr_tail(bytes: &[u8]) -> String {
    const MAX: usize = 160;
    for line in bytes.split(|byte| *byte == b'\n').rev() {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let cleaned: String = line
            .iter()
            .filter(|byte| **byte == b' ' || byte.is_ascii_graphic())
            .map(|byte| *byte as char)
            .collect();
        let cleaned = cleaned.trim().to_string();
        if cleaned.is_empty() {
            continue;
        }
        // An overlong line keeps its end: the client states the verdict last.
        if cleaned.len() <= MAX {
            return cleaned;
        }
        return cleaned[cleaned.len() - MAX..].to_string();
    }
    String::new()
}

#[derive(Clone, Copy, Default)]
struct Observation {
    forwarding_refused: bool,
    ended: bool,
}

pub struct Diagnostics {
    observation: watch::Receiver<Observation>,
    task: Option<JoinHandle<std::io::Result<()>>>,
}

impl Diagnostics {
    pub fn start(mut stderr: impl tokio::io::AsyncRead + Unpin + Send + 'static) -> Self {
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

    pub async fn forwarding_refusal(&mut self, port: u16) -> Option<SeError> {
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

    pub async fn close(&mut self) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::{read_errors, sanitized_stderr_tail};
    use se_types::Detail;

    #[test]
    fn tail_is_the_last_non_empty_line() {
        let bytes = b"Warning: Permanently added '127.0.0.1' (ED25519) to the list of known hosts.\nuser@host: Permission denied (publickey).\n";
        assert_eq!(
            sanitized_stderr_tail(bytes),
            "user@host: Permission denied (publickey)."
        );
    }

    #[test]
    fn tail_strips_carriage_returns() {
        let bytes = b"line one\r\nuser@host: Permission denied (publickey).\r\n";
        assert_eq!(
            sanitized_stderr_tail(bytes),
            "user@host: Permission denied (publickey)."
        );
    }

    #[test]
    fn tail_keeps_only_printable_ascii() {
        let bytes = b"ssh: connect to host \xc3\xa9xample port 22: Connection refused";
        let tail = sanitized_stderr_tail(bytes);
        assert!(
            tail.bytes()
                .all(|byte| byte == b' ' || (0x21..=0x7e).contains(&byte)),
            "{tail:?}"
        );
        assert!(tail.contains("Connection refused"), "{tail:?}");
    }

    #[test]
    fn tail_keeps_the_end_of_an_overlong_line() {
        let line = "a".repeat(300);
        let bytes = format!("prefix\n{line}").into_bytes();
        let tail = sanitized_stderr_tail(&bytes);
        assert_eq!(tail.len(), 160);
        assert!(tail.chars().all(|character| character == 'a'));
    }

    #[test]
    fn tail_is_empty_without_readable_lines() {
        assert_eq!(sanitized_stderr_tail(b""), "");
        assert_eq!(sanitized_stderr_tail(b"\n\r\n"), "");
        assert_eq!(sanitized_stderr_tail(b"\xff\xfe"), "");
    }

    #[tokio::test]
    async fn read_errors_returns_the_sanitized_tail() {
        let bytes = b"user@host: Permission denied (publickey).\n";
        let tail = match read_errors("dest", tokio::io::BufReader::new(&bytes[..])).await {
            Ok(tail) => tail,
            Err(error) => panic!("read_errors refused: {error:?}"),
        };
        assert_eq!(tail, "user@host: Permission denied (publickey).");
    }

    #[tokio::test]
    async fn read_errors_still_refuses_hostname_diagnostics() {
        let bytes =
            b"ssh: Could not resolve hostname pairdest: Temporary failure in name resolution\n";
        let error = match read_errors("pairdest", tokio::io::BufReader::new(&bytes[..])).await {
            Ok(_) => panic!("read_errors accepted a hostname refusal"),
            Err(error) => error,
        };
        match error.body.detail() {
            Detail::ListenerUnavailable(detail) => {
                assert!(
                    detail
                        .reason
                        .contains("could not resolve the host name for pairdest"),
                    "{}",
                    detail.reason
                );
            }
            other => panic!("expected listener-unavailable, got {other:?}"),
        }
    }
}
