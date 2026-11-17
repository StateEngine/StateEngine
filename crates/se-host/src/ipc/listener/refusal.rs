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
        match socket.shutdown(std::net::Shutdown::Write) {
            Ok(()) => (),
            // The client may consume the refusal and close before half-close.
            Err(error) if error.kind() == std::io::ErrorKind::NotConnected => return Ok(()),
            Err(error) => return Err(wire::io_failure("finish IPC refusal write", error)),
        }
    }
    #[cfg(target_os = "macos")]
    {
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
    // Linux SO_PEERCRED and the named-pipe server PID survive ordinary peer
    // close. The pipe reactor also completes pending writes before handle close.
    Ok(())
}
