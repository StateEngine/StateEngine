//! Digest hints for the hook and provider images, independent of the host image.
//! Native process identity, birth, ancestry and admission are never cached.
use super::{
    image::{key, remember},
    image_cache::{Entry, read, store},
    *,
};
use crate::{NativeStateFiles, OwnedFile, StateFileErrorCode};
use sha2::{Digest, Sha256 as Hasher};
use std::{fs::File, time::Duration};

const HOOK: &str = "ipc-adoption-hook-image.json";
fn provider_name(provider: &Path) -> IpcNativeResult<String> {
    let path = se_types::NativePath::from_local(provider.to_owned())
        .map_err(|e| error("encode selected provider path", std::io::Error::other(e)))?;
    let bytes = serde_json::to_vec(&path).map_err(|e| {
        error(
            "encode selected provider cache path",
            std::io::Error::other(e),
        )
    })?;
    Ok(format!(
        "ipc-adoption-provider-{:x}.json",
        Hasher::digest(bytes)
    ))
}
const LOCK: &str = "ipc-adoption-image.lock";

/// Warm both selected images at explicit installation or after an image update.
/// Concurrent fresh hooks share one cold read; unchanged native file keys need
/// only protected metadata reads. Other runtime image hints remain untouched.
pub fn prepare_adoption_image_cache(
    root: &Path,
    provider: &Path,
    bound: &IpcIoBound,
) -> IpcNativeResult<()> {
    let image = std::env::current_exe().map_err(|e| error("locate hook executable", e))?;
    prepare(root, HOOK, &image, bound)?;
    prepare(root, &provider_name(provider)?, provider, bound)
}

/// The serving host restores the provider hint before its short native ancestry
/// proof. A stale hint cannot match the retained provider file's native key.
pub fn restore_adoption_provider_cache(
    root: &Path,
    provider: &Path,
    bound: &IpcIoBound,
) -> IpcNativeResult<ImageCacheRead> {
    let files = NativeStateFiles::open(root)
        .map_err(|e| error("pin adoption image cache home", std::io::Error::other(e)))?;
    restore(&files, &provider_name(provider)?, provider, bound)
}

fn restore(
    files: &NativeStateFiles,
    name: &str,
    path: &Path,
    bound: &IpcIoBound,
) -> IpcNativeResult<ImageCacheRead> {
    bound
        .remaining()
        .map_err(|e| error("adoption image cache deadline", e))?;
    let Some(bytes) = read(files, name)? else {
        return Ok(ImageCacheRead::Absent);
    };
    let Ok(entry) = serde_json::from_slice::<Entry>(&bytes) else {
        return Ok(ImageCacheRead::Stale);
    };
    if entry.schema != 1 {
        return Ok(ImageCacheRead::Stale);
    }
    let held = File::open(path).map_err(|e| error("pin selected adoption image", e))?;
    let metadata = held
        .metadata()
        .map_err(|e| error("read adoption image metadata", e))?;
    if !metadata.is_file() || key(&held, &metadata)? != entry.image {
        return Ok(ImageCacheRead::Stale);
    }
    // hash_image independently pins and checks this same native key again.
    remember(entry.image, entry.digest)?;
    bound
        .remaining()
        .map_err(|e| error("finish adoption image cache restore", e))?;
    Ok(ImageCacheRead::Current)
}

fn prepare(root: &Path, name: &str, path: &Path, bound: &IpcIoBound) -> IpcNativeResult<()> {
    let files = NativeStateFiles::open(root)
        .map_err(|e| error("pin adoption image cache home", std::io::Error::other(e)))?;
    if restore(&files, name, path, bound)? == ImageCacheRead::Current {
        return Ok(());
    }
    let _lock = lock(&files, bound)?;
    // A parallel hook may have finished the cold proof while this hook waited.
    if restore(&files, name, path, bound)? == ImageCacheRead::Current {
        return Ok(());
    }
    let held = File::open(path).map_err(|e| error("pin changed adoption image", e))?;
    let stamp = key(
        &held,
        &held
            .metadata()
            .map_err(|e| error("read changed image metadata", e))?,
    )?;
    let digest = hash_image(held, bound)?;
    let again = File::open(path).map_err(|e| error("reobserve selected adoption image", e))?;
    if key(
        &again,
        &again
            .metadata()
            .map_err(|e| error("reobserve adoption image metadata", e))?,
    )? != stamp
    {
        return Err(refuse(
            IpcNativeErrorCode::PeerChanged,
            "selected adoption image changed during proof; retry the native session",
        ));
    }
    store(
        &files,
        name,
        &Entry {
            schema: 1,
            image: stamp,
            digest,
        },
        bound,
    )
}

fn lock(files: &NativeStateFiles, bound: &IpcIoBound) -> IpcNativeResult<File> {
    let path = files.root().join(LOCK);
    if files
        .readback(&path)
        .map_err(|e| error("read adoption cache lock", std::io::Error::other(e)))?
        .is_none()
    {
        let staged = files
            .create_staging(files.root())
            .map_err(|e| error("stage adoption cache lock", std::io::Error::other(e)))?;
        staged
            .file
            .sync_all()
            .map_err(|e| error("flush adoption cache lock", e))?;
        drop(staged.file);
        match files.publish_no_replace(&staged.path, &path) {
            Ok(()) => (),
            Err(cause) if cause.code == StateFileErrorCode::AlreadyExists => {
                if let Some(file) = OwnedFile::open(&staged.path)
                    .map_err(|e| error("pin unused cache staging", std::io::Error::other(e)))?
                {
                    file.remove(Hasher::digest([]).into()).map_err(|e| {
                        error("remove unused cache staging", std::io::Error::other(e))
                    })?;
                }
            }
            Err(cause) => {
                return Err(error(
                    "publish adoption cache lock",
                    std::io::Error::other(cause),
                ));
            }
        }
    }
    let file = files
        .readback(&path)
        .map_err(|e| error("pin adoption cache lock", std::io::Error::other(e)))?
        .ok_or_else(|| {
            refuse(
                IpcNativeErrorCode::PeerChanged,
                "adoption cache lock disappeared",
            )
        })?;
    loop {
        bound
            .remaining()
            .map_err(|e| error("wait for changed image proof", e))?;
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(10)),
            Err(std::fs::TryLockError::Error(cause)) => {
                return Err(error("lock adoption image cache", cause));
            }
        }
    }
}
