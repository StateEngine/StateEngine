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
        if !ssh(
            destination,
            staging::prepare(&image.directory(), true, false),
        )
        .await?
        .0
        {
            return Err(unsafe_cache());
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
        return Err(unsafe_cache());
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
