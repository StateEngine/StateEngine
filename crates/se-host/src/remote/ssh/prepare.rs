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
    if !ssh(
        destination,
        staging::prepare(&image.directory(), image.windows, image.apple),
    )
    .await?
    .0
    {
        return Err(unavailable(
            "remote runtime cache ownership or permissions refused; preserve unsafe paths and restore an account-owned directory without foreign write access",
        ));
    }
    let verify = staging::verify(&image.remote(), &image.digest, image.windows, image.apple);
    if ssh(destination, verify.clone()).await?.0 {
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
        super::upload::send(destination, &mut image, &upload, cancelled, progress).await?;
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
        let (verified, detail) = ssh(
            destination,
            staging::verify(&upload, &image.digest, image.windows, image.apple),
        )
        .await?;
        if !verified {
            return Err(super::command::verification_error(&detail));
        }
        // Never overwrite an incumbent; a concurrent uploader may publish first.
        let _published = ssh(
            destination,
            staging::publish(&upload, &image.remote(), image.windows),
        )
        .await?;
        let (verified, detail) = ssh(destination, verify).await?;
        if !verified {
            return Err(super::command::verification_error(&detail));
        }
        Ok(())
    }
    .await;
    let cleanup = ssh(destination, staging::remove(&upload, image.windows)).await;
    match (result, cleanup) {
        (Err(error), _) => return Err(error),
        (Ok(()), Ok((true, _))) => (),
        (Ok(()), _) => {
            return Err(unavailable(
                "native image verified, but its owned upload cleanup is incomplete; retry setup with the original machine name",
            ));
        }
    }
    progress(ImageProgress {
        stage: ImageStage::Ready,
        bytes_streamed: image.expected,
        total_bytes: Some(image.expected),
        elapsed_ms: 0,
    })?;
    Ok(())
}
