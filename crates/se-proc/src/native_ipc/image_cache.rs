//! Protected digest hints extend native file-identity proofs across fresh CLIs.
//! A remote bootstrap copy has its own bounded hint, never replacing the host hint.
use super::image::{ImageKey, key, remember};
use super::*;
use crate::{NativeStateFiles, OwnedFile};
use sha2::{Digest, Sha256 as Hasher};
use std::{
    fs::File,
    io::{Read, Write},
};
const NAME: &str = "ipc-image-cache.json";
const REMOTE_NAME: &str = "ipc-remote-image-cache.json";
const MAX_BYTES: usize = 4096;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Entry {
    pub(super) schema: u16,
    pub(super) image: ImageKey,
    pub(super) digest: Sha256,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageCacheRead {
    Absent,
    Current,
    Stale,
}
pub(super) fn read(files: &NativeStateFiles, name: &str) -> IpcNativeResult<Option<Vec<u8>>> {
    let Some(file) = files
        .readback(&files.root().join(name))
        .map_err(|e| error("read protected executable cache", std::io::Error::other(e)))?
    else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| error("read executable cache bytes", e))?;
    if bytes.len() > MAX_BYTES {
        return Err(refuse(
            IpcNativeErrorCode::Unreadable,
            "protected executable cache exceeds 4096 bytes; stop and restore its original bounded file",
        ));
    }
    Ok(Some(bytes))
}
/// Only the exclusive runtime-lease owner calls publication. Its current
/// executable is hashed through a retained native file before replacing a hint.
pub fn publish_image_cache(
    root: &Path,
    expected: Sha256,
    bound: &IpcIoBound,
) -> IpcNativeResult<()> {
    publish(root, NAME, expected, bound)
}
/// After successful native Owner bootstrap, retain the actual uploaded CLI's
/// independently hashed file identity. This does not replace the host hint or
/// cache PID, birth, generation, owner admission, credentials or channel authority.
pub fn publish_remote_image_cache(
    root: &Path,
    expected: Sha256,
    bound: &IpcIoBound,
) -> IpcNativeResult<ImageCacheRead> {
    // A compatible incumbent can run a different image. Its endpoint hint
    // cannot qualify this CLI, so retain the normal cold proof in that case.
    if observe_ipc_self_bounded(bound)?.image_sha256() != expected {
        return Ok(ImageCacheRead::Stale);
    }
    publish(root, REMOTE_NAME, expected, bound)?;
    Ok(ImageCacheRead::Current)
}
fn publish(root: &Path, name: &str, expected: Sha256, bound: &IpcIoBound) -> IpcNativeResult<()> {
    bound
        .remaining()
        .map_err(|e| error("publish executable cache deadline", e))?;
    let files = NativeStateFiles::open(root)
        .map_err(|e| error("pin executable cache home", std::io::Error::other(e)))?;
    let path =
        std::env::current_exe().map_err(|e| error("read current executable cache path", e))?;
    let held = File::open(path).map_err(|e| error("pin current executable for cache", e))?;
    let stamp = key(
        &held,
        &held
            .metadata()
            .map_err(|e| error("read current executable cache metadata", e))?,
    )?;
    let digest = hash_image(
        held.try_clone()
            .map_err(|e| error("duplicate executable cache pin", e))?,
        bound,
    )?;
    if digest != expected
        || key(
            &held,
            &held
                .metadata()
                .map_err(|e| error("reobserve cached executable metadata", e))?,
        )? != stamp
    {
        return Err(refuse(
            IpcNativeErrorCode::PeerChanged,
            "current executable differs from the runtime's measured image",
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
pub(super) fn store(
    files: &NativeStateFiles,
    name: &str,
    entry: &Entry,
    bound: &IpcIoBound,
) -> IpcNativeResult<()> {
    let root = files.root();
    let bytes = serde_json::to_vec(entry)
        .map_err(|e| error("encode executable cache", std::io::Error::other(e)))?;
    let prior = read(files, name)?;
    bound
        .remaining()
        .map_err(|e| error("publish executable cache deadline", e))?;
    let target = root.join(name);
    match prior {
        Some(prior) => {
            let file = OwnedFile::open(&target)
                .map_err(|e| error("pin prior executable cache", std::io::Error::other(e)))?
                .ok_or_else(|| {
                    refuse(
                        IpcNativeErrorCode::PeerChanged,
                        "executable cache disappeared before replacement",
                    )
                })?;
            file.replace(Hasher::digest(&prior).into(), &bytes)
                .map_err(|e| {
                    error(
                        "replace protected executable cache",
                        std::io::Error::other(e),
                    )
                })?;
        }
        None => {
            let mut staged = files
                .create_staging(root)
                .map_err(|e| error("stage executable cache", std::io::Error::other(e)))?;
            staged
                .file
                .write_all(&bytes)
                .and_then(|()| staged.file.sync_all())
                .map_err(|e| error("write executable cache staging", e))?;
            drop(staged.file);
            files
                .publish_no_replace(&staged.path, &target)
                .map_err(|e| {
                    error(
                        "publish protected executable cache",
                        std::io::Error::other(e),
                    )
                })?;
        }
    }
    bound
        .remaining()
        .map_err(|e| error("finish executable cache publication", e))?;
    Ok(())
}
/// Restore a bounded protected hint, never PID, birth, credential, generation,
/// ancestry or authorization. hash_image still pins/rechecks the actual file's
/// identity, size and exact modification/change timestamps before using this digest.
/// Legacy hints without change time cannot match a fresh native key.
/// Endpoint/native instance and MAC checks remain required.
pub fn restore_image_cache(
    root: &Path,
    expected: Sha256,
    bound: &IpcIoBound,
) -> IpcNativeResult<ImageCacheRead> {
    restore(root, NAME, expected, bound)
}
/// Restore only the separate uploaded-image hint. A changed native file key
/// misses exactly as for the host hint; callers must still authenticate IPC.
pub fn restore_remote_image_cache(
    root: &Path,
    expected: Sha256,
    bound: &IpcIoBound,
) -> IpcNativeResult<ImageCacheRead> {
    restore(root, REMOTE_NAME, expected, bound)
}
fn restore(
    root: &Path,
    name: &str,
    expected: Sha256,
    bound: &IpcIoBound,
) -> IpcNativeResult<ImageCacheRead> {
    bound
        .remaining()
        .map_err(|e| error("restore executable cache deadline", e))?;
    let files = NativeStateFiles::open(root)
        .map_err(|e| error("pin executable cache home", std::io::Error::other(e)))?;
    let Some(bytes) = read(&files, name)? else {
        return Ok(ImageCacheRead::Absent);
    };
    let entry: Entry = serde_json::from_slice(&bytes).map_err(|e| {
        error(
            "decode protected executable cache",
            std::io::Error::other(e),
        )
    })?;
    if entry.schema != 1 {
        return Err(refuse(
            IpcNativeErrorCode::Unreadable,
            "unsupported protected executable cache schema",
        ));
    }
    bound
        .remaining()
        .map_err(|e| error("finish executable cache restore", e))?;
    if entry.digest != expected {
        return Ok(ImageCacheRead::Stale);
    };
    remember(entry.image, entry.digest)?;
    Ok(ImageCacheRead::Current)
}
