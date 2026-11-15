//! Image staging is a native CLI stage, outside the short pairing IPC request.
use super::command::ssh;
use super::*;
use std::{
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageStage {
    Discovering,
    Cached,
    Uploading,
    Verifying,
    Ready,
}

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct ImageProgress {
    pub stage: ImageStage,
    /// Bytes accepted by the owned SSH stream, not a remote publication receipt.
    pub bytes_streamed: u64,
    pub total_bytes: Option<u64>,
    pub elapsed_ms: u64,
}

pub async fn prepare_image(
    destination: &str,
    distribution: &Path,
    cancelled: &AtomicBool,
    progress: &mut dyn FnMut(ImageProgress) -> Result<()>,
) -> Result<()> {
    progress(ImageProgress {
        stage: ImageStage::Discovering,
        bytes_streamed: 0,
        total_bytes: None,
        elapsed_ms: 0,
    })?;
    let mut image = super::image::describe(destination, distribution).await?;
    if cancelled.load(Ordering::Acquire) {
        return Err(unavailable("remote image preparation was cancelled"));
    }
    if cached_image(destination, &image).await? {
        progress(ImageProgress {
            stage: ImageStage::Cached,
            bytes_streamed: 0,
            total_bytes: Some(image.expected),
            elapsed_ms: 0,
        })?;
        return Ok(());
    }
    let upload = format!(
        "{}.upload-{}",
        image.remote(),
        se_types::hex_lower(&crate::remote::session::entropy::<16>()?)
    );
    let result = async {
        super::command::send_image(destination, &mut image, &upload, cancelled, progress).await?;
        if cancelled.load(Ordering::Acquire) {
            return Err(unavailable(
                "remote image preparation was cancelled before publication",
            ));
        }
        progress(ImageProgress {
            stage: ImageStage::Verifying,
            bytes_streamed: image.expected,
            total_bytes: Some(image.expected),
            elapsed_ms: 0,
        })?;
        publish_image(destination, &image, &upload).await
    }
    .await;
    if let Err(error) = result {
        // A lost response or cancelled stream leaves no cleanup witness. Retry
        // removal of this invocation's nonce only; retain the original refusal.
        let _cleanup = ssh(destination, staging::remove(&upload, image.windows)).await;
        return Err(error);
    }
    progress(ImageProgress {
        stage: ImageStage::Ready,
        bytes_streamed: image.expected,
        total_bytes: Some(image.expected),
        elapsed_ms: 0,
    })?;
    Ok(())
}

fn cleanup_incomplete() -> se_types::SeError {
    unavailable(
        "native image verified, but its owned upload cleanup is incomplete; retry setup with the original machine name",
    )
}

async fn cached_image(destination: &str, image: &super::image::Image) -> Result<bool> {
    // Windows retains its existing encoded commands. Nesting their encodings
    // inside a batch can exceed the native command interpreter's length bound.
    if image.windows {
        let (prepared, detail) = ssh(
            destination,
            staging::prepare(&image.directory(), true, false),
        )
        .await?;
        if !prepared {
            return Err(cache_refusal(&detail).unwrap_or_else(unsafe_cache));
        }
        return Ok(ssh(
            destination,
            staging::verify(&image.remote(), &image.digest, true, false),
        )
        .await?
        .0);
    }
    let (cached, detail) = ssh(
        destination,
        image_commands::cached(
            &image.directory(),
            &image.remote(),
            &image.digest,
            image.apple,
        ),
    )
    .await?;
    if !detail.starts_with(image_commands::CACHE_PREPARED) {
        return Err(cache_refusal(&detail).unwrap_or_else(unsafe_cache));
    }
    Ok(cached)
}

async fn publish_image(destination: &str, image: &super::image::Image, upload: &str) -> Result<()> {
    if image.windows {
        verify_image(destination, image, upload).await?;
        let _published = ssh(destination, staging::publish(upload, &image.remote(), true)).await?;
        verify_image(destination, image, &image.remote()).await?;
        return match ssh(destination, staging::remove(upload, true)).await {
            Ok((true, _)) => Ok(()),
            _ => Err(cleanup_incomplete()),
        };
    }
    let (verified, detail) = ssh(
        destination,
        image_commands::publish(upload, &image.remote(), &image.digest, image.apple),
    )
    .await?;
    if verified {
        return Ok(());
    }
    if image_commands::has_marker(&detail, image_commands::CLEANUP_FAILED)
        && !image_commands::has_marker(&detail, image_commands::VERIFY_FAILED)
    {
        return Err(cleanup_incomplete());
    }
    Err(super::command::verification_error(&detail))
}

async fn verify_image(destination: &str, image: &super::image::Image, path: &str) -> Result<()> {
    let (verified, detail) = ssh(
        destination,
        staging::verify(path, &image.digest, image.windows, image.apple),
    )
    .await?;
    if verified {
        Ok(())
    } else {
        Err(super::command::verification_error(&detail))
    }
}

fn unsafe_cache() -> se_types::SeError {
    unavailable(
        "remote runtime cache ownership or permissions refused; preserve unsafe paths and restore an account-owned directory without foreign write access",
    )
}

/// A refused prepare names the failing check and the destination path on a
/// fixed marker line; anything else stays the general unsafe-cache refusal.
pub(in crate::remote) fn cache_refusal(detail: &[u8]) -> Option<se_types::SeError> {
    let line = detail
        .split(|byte| *byte == b'\n')
        .find_map(|line| line.strip_prefix(b"image-cache-refused:"))?;
    let text = String::from_utf8_lossy(line);
    let fields: Vec<&str> = text.split(':').collect();
    let reason = fields.first().copied()?;
    // The path is positional but colon-bearing (Windows drive letters);
    // only the two numeric extras trail it, so split-join loss is impossible.
    let (path_fields, extra) = if matches!(reason, "foreign-owner" | "group-or-other-writable") {
        if fields.len() < 3 {
            return None;
        }
        (&fields[1..fields.len() - 1], Some(fields.last().copied()?))
    } else {
        (&fields[1..], None)
    };
    let path = path_fields.join(":");
    if path.is_empty() {
        return None;
    }
    let (reason_text, next_step) = match (reason, extra) {
        ("create-failed", _) => (
            format!("could not create the runtime directory {path}"),
            "check that the destination account can write the parent directory and that disk space is available, then retry with the original machine name".to_owned(),
        ),
        ("mode-confirm", _) => (
            format!("the runtime directory {path} was created without the required mode 700 and could not be corrected"),
            format!("run `chmod 700 {path}` on the destination, then retry with the original machine name"),
        ),
        ("symlink", _) => (
            format!("the runtime path {path} is a symlink"),
            format!("replace {path} with a real account-owned directory created by `mkdir -m 700`, then retry with the original machine name"),
        ),
        ("stat-failed", _) => (
            format!("the runtime path {path} could not be inspected"),
            format!("verify that {path} exists as a directory readable by the destination account, then retry with the original machine name"),
        ),
        ("foreign-owner", Some(owner)) => (
            format!("the runtime path {path} is owned by account uid {owner} instead of the destination account"),
            format!("restore {path} to the destination account with chown, or remove it if it is not in use, then retry with the original machine name"),
        ),
        ("group-or-other-writable", Some(mode)) => (
            format!("the runtime path {path} has mode {mode}, which permits group or other writes"),
            format!("run `chmod go-w {path}` on the destination and on any group-writable ancestor, then retry with the original machine name"),
        ),
        ("unsafe-path", _) => (
            format!("the runtime path {path} is not a plain directory"),
            format!("replace {path} with a real account-owned directory, then retry with the original machine name"),
        ),
        ("foreign-write-access", _) => (
            format!("the runtime path {path} grants write access to an account outside the destination account, root, and administrators"),
            format!("remove the foreign write entries from {path}, then retry with the original machine name"),
        ),
        _ => return None,
    };
    Some(se_types::SeError::new(
        se_types::Detail::ListenerUnavailable(se_types::details::ListenerUnavailable {
            subject: "remote runtime cache".into(),
            reason: reason_text,
            next_step,
        }),
    ))
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    reason = "test setup and assertions retain the failing fs operation"
)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn listener_detail(error: &se_types::SeError) -> &se_types::details::ListenerUnavailable {
        match error.body.detail() {
            se_types::Detail::ListenerUnavailable(detail) => detail,
            other => panic!("expected listener-unavailable detail, got {other:?}"),
        }
    }

    #[test]
    fn cache_refusal_names_the_check_path_and_step() {
        let refusal = cache_refusal(
            b"image-cache-refused:group-or-other-writable:/home/u/.stateengine-runtime:775\n",
        )
        .expect("marker line must parse");
        let detail = listener_detail(&refusal);
        assert!(detail.reason.contains("/home/u/.stateengine-runtime"));
        assert!(detail.reason.contains("775"));
        assert!(detail.reason.contains("group or other writes"));
        assert!(detail.next_step.contains("chmod go-w"));
    }

    #[test]
    fn cache_refusal_names_the_foreign_owner() {
        let refusal = cache_refusal(
            b"image-cache-refused:foreign-owner:/home/u/.stateengine-runtime/abc:1003\n",
        )
        .expect("marker line must parse");
        let detail = listener_detail(&refusal);
        assert!(detail.reason.contains("uid 1003"));
        assert!(detail.reason.contains("/home/u/.stateengine-runtime/abc"));
        assert!(detail.next_step.contains("chown"));
    }

    #[test]
    fn cache_refusal_stays_general_for_unmarked_output() {
        assert!(cache_refusal(b"").is_none());
        assert!(cache_refusal(b"some other failure\n").is_none());
        assert!(cache_refusal(b"image-cache-refused:\n").is_none());
        assert!(cache_refusal(b"image-cache-refused:unknown-reason:/home/u/.x\n").is_none());
    }

    #[test]
    fn prepare_scripts_create_explicitly_and_name_refusals() {
        let unix = staging::prepare(".stateengine-runtime/abc", false, false);
        assert!(unix.contains("mkdir -m 700"));
        assert!(!unix.contains("umask 077 && mkdir"));
        assert!(unix.contains("image-cache-refused:create-failed:"));
        assert!(unix.contains("image-cache-refused:group-or-other-writable:"));
        let apple = staging::prepare(".stateengine-runtime/abc", false, true);
        assert!(apple.contains("mkdir -m 700"));
        assert!(apple.contains("stat -f"));
        let windows = staging::prepare_windows(".stateengine-runtime/abc");
        assert!(windows.contains("image-cache-refused:"));
        assert!(!windows.contains("throw '"));
    }

    fn run_prepare(home: &std::path::Path) -> std::process::Output {
        let script = staging::prepare(".stateengine-runtime/deadbeef", false, false);
        std::process::Command::new("bash")
            .arg("-c")
            .arg(format!("cd {} && {}", home.display(), script))
            .output()
            .expect("run prepare script")
    }

    #[cfg(unix)]
    #[test]
    fn prepare_creates_tight_directories_under_group_writable_umask() {
        let root = std::env::temp_dir().join(format!("se-381-prepare-{}", std::process::id()));
        let home = root.join("home");
        std::fs::create_dir_all(&home).expect("test home");
        // The script checks the home directory itself; 755 passes the mode
        // gate regardless of this process's ambient umask.
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o755)).expect("home mode");
        let script = staging::prepare(".stateengine-runtime/deadbeef", false, false);
        let output = std::process::Command::new("bash")
            .arg("-c")
            .arg(format!("cd {} && umask 002 && {}", home.display(), script))
            .output()
            .expect("run prepare script");
        let result = (output.status.success(), output);
        assert!(result.0, "prepare failed: {:?}", result.1);
        for dir in [".stateengine-runtime", ".stateengine-runtime/deadbeef"] {
            let meta = std::fs::metadata(home.join(dir)).expect("created dir");
            assert_eq!(
                meta.permissions().mode() & 0o777,
                0o700,
                "{dir} must be 700"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn prepare_refusal_names_the_group_writable_directory() {
        let root =
            std::env::temp_dir().join(format!("se-381-prepare-refusal-{}", std::process::id()));
        let home = root.join("home");
        std::fs::create_dir_all(home.join(".stateengine-runtime")).expect("precreate");
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o755)).expect("home mode");
        // Mode 775: what an ambient umask 002 leaves behind.
        std::fs::set_permissions(
            home.join(".stateengine-runtime"),
            std::fs::Permissions::from_mode(0o775),
        )
        .expect("mode");
        let output = run_prepare(&home);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let _ = std::fs::remove_dir_all(&root);
        assert!(!output.status.success(), "prepare must refuse");
        assert!(
            stdout.contains("image-cache-refused:group-or-other-writable:.stateengine-runtime:775"),
            "stdout: {stdout}"
        );
    }
}
