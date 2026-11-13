//! Bounded fixed SSH commands retain and join their native child.
use super::*;
use se_types::SeError;
use tokio::io::AsyncReadExt;

pub(super) async fn output(program: &str, arguments: &[String]) -> Result<(bool, Vec<u8>)> {
    let mut child = Command::new(program)
        .args(arguments)
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
        let mut errors = Vec::new();
        let mut stdout = stdout.take(65537);
        let mut stderr = stderr.take(4097);
        tokio::try_join!(
            stdout.read_to_end(&mut bytes),
            stderr.read_to_end(&mut errors)
        )
        .map_err(|_| unavailable("SSH output could not be read"))?;
        if bytes.len() > 65536 || errors.len() > 4096 {
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
            if child
                .try_wait()
                .map_err(|_| unavailable("SSH custody unreadable"))?
                .is_none()
            {
                child
                    .start_kill()
                    .map_err(|_| unavailable("cannot close owned SSH bootstrap"))?;
            }
            child
                .wait()
                .await
                .map_err(|_| unavailable("cannot join SSH bootstrap"))?;
            match other {
                Ok(Err(error)) => Err(error),
                _ => Err(unavailable("SSH bootstrap exceeded 25 seconds")),
            }
        }
    }
}
pub(super) async fn ssh(destination: &str, command: String) -> Result<(bool, Vec<u8>)> {
    validate_destination(destination)?;
    output(
        "ssh",
        &[
            "-T".into(),
            "-o".into(),
            "BatchMode=yes".into(),
            destination.into(),
            command,
        ],
    )
    .await
}

pub(super) fn verification_error(bytes: &[u8]) -> SeError {
    if let Some(mode) = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.trim().strip_prefix("unsafe-mode:"))
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
