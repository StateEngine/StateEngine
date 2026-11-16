//! Preserve native peer proof until a refused client consumes its reply.
use super::*;

pub(super) async fn send_refusal(
    stream: &NativeStream,
    frame: &wire::WireBytes,
    deadline: &Deadline,
) -> Result<()> {
    send(stream, frame, deadline).await?;
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsFd;
        // Half-close only: LOCAL_PEERPID needs the server socket to remain open.
        let socket = std::os::unix::net::UnixStream::from(
            stream
                .as_fd()
                .try_clone_to_owned()
                .map_err(|error| wire::io_failure("retain refused IPC socket", error))?,
        );
        socket
            .shutdown(std::net::Shutdown::Write)
            .map_err(|error| wire::io_failure("finish IPC refusal write", error))?;
    }
    #[cfg(any(target_os = "macos", windows))]
    {
        // Named pipes have no write half-close. Keep the connected server handle
        // instead: disconnect can invalidate PID proof and discard unread data.
        let until = tokio::time::Instant::from_std(deadline.at())
            .min(tokio::time::Instant::now() + std::time::Duration::from_secs(1));
        let _ = tokio::time::timeout_at(until, async {
            let mut bytes = [0; 1024];
            loop {
                if stream.readable().await.is_err() {
                    break;
                }
                match stream.try_read(&mut bytes) {
                    Ok(0) => break,
                    Err(error)
                        if !matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) =>
                    {
                        break;
                    }
                    _ => tokio::task::yield_now().await,
                }
            }
        })
        .await;
    }
    // Linux SO_PEERCRED survives peer close; no retention is needed there.
    Ok(())
}
