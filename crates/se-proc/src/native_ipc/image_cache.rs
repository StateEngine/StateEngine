//! One protected host-published digest hint extends the existing file-identity
//! cache across fresh CLI processes. It grants no process or caller authority.
use super::image::{ImageKey, key, remember};
use super::*;
use crate::{NativeStateFiles, OwnedFile};
use sha2::{Digest, Sha256 as Hasher};
use std::{
    fs::File,
    io::{Read, Write},
};
const NAME: &str = "ipc-image-cache.json";
const MAX_BYTES: usize = 4096;
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    schema: u16,
    image: ImageKey,
    digest: Sha256,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageCacheRead {
    Absent,
    Current,
    Stale,
}
fn read(files: &NativeStateFiles) -> IpcNativeResult<Option<Vec<u8>>> {
    let Some(file) = files
        .readback(&files.root().join(NAME))
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
    let bytes = serde_json::to_vec(&Entry {
        schema: 1,
        image: stamp,
        digest,
    })
    .map_err(|e| error("encode executable cache", std::io::Error::other(e)))?;
    let prior = read(&files)?;
    bound
        .remaining()
        .map_err(|e| error("publish executable cache deadline", e))?;
    let target = root.join(NAME);
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
    bound
        .remaining()
        .map_err(|e| error("restore executable cache deadline", e))?;
    let files = NativeStateFiles::open(root)
        .map_err(|e| error("pin executable cache home", std::io::Error::other(e)))?;
    let Some(bytes) = read(&files)? else {
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
