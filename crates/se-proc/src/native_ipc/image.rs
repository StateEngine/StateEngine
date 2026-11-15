//! Bounded executable proofs. Unix reuse requires stable native file identity,
//! modification/change times and size. Windows reuse requires a positive journal
//! revision while a retained native handle excludes writers. Unsupported revisions
//! fall back to reading the bytes. A pathname is never a cache identity.
//! Unix change time invalidates same-inode rewrites even when mtime is restored;
//! it is not a qualified persistent journal or protection against hostile same-user mutation.
use super::*;
use sha2::{Digest, Sha256 as Hasher};
use std::{
    collections::VecDeque,
    fs::File,
    sync::{Mutex, OnceLock},
    time::UNIX_EPOCH,
};
#[derive(Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ImageKey {
    identity: Vec<u8>,
    modified: (bool, u64, u32),
    size: u64,
    // Unix ctime/nanoseconds, or a Windows journal revision tagged with 1.
    // Legacy Windows clock keys used tag 0; absent revisions cannot qualify reuse.
    #[serde(default)]
    changed: Option<(i64, i64)>,
}
#[cfg(windows)]
mod windows;
impl ImageKey {
    pub(super) fn reusable(&self) -> bool {
        #[cfg(windows)]
        {
            // Tag 1 is a positive journal revision; legacy file clocks used tag 0.
            matches!(self.changed, Some((revision, 1)) if revision > 0)
        }
        #[cfg(not(windows))]
        {
            true
        }
    }
}
type Cache = VecDeque<(ImageKey, Sha256)>;
static CACHE: OnceLock<Mutex<Cache>> = OnceLock::new();
pub(super) fn key(file: &File, metadata: &std::fs::Metadata) -> IpcNativeResult<ImageKey> {
    #[cfg(unix)]
    let identity = {
        use std::os::unix::fs::MetadataExt;
        [metadata.dev().to_be_bytes(), metadata.ino().to_be_bytes()].concat()
    };
    #[cfg(windows)]
    let identity = {
        use std::{mem::size_of, os::windows::io::AsRawHandle};
        use windows_sys::Win32::Storage::FileSystem::*;
        let mut id = FILE_ID_INFO {
            VolumeSerialNumber: 0,
            FileId: FILE_ID_128 {
                Identifier: [0; 16],
            },
        };
        // SAFETY: retained file handle, aligned initialized FILE_ID_INFO output and exact byte size.
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileIdInfo,
                (&mut id as *mut FILE_ID_INFO).cast(),
                size_of::<FILE_ID_INFO>() as u32,
            )
        } == 0
        {
            return Err(last("read executable cache file identity"));
        }
        [
            id.VolumeSerialNumber.to_be_bytes().as_slice(),
            &id.FileId.Identifier,
        ]
        .concat()
    };
    #[cfg(unix)]
    let changed = {
        use std::os::unix::fs::MetadataExt;
        Some((metadata.ctime(), metadata.ctime_nsec()))
    };
    #[cfg(windows)]
    let changed = windows::revision(file).map(|revision| (revision, 1));
    let _ = file;
    Ok(ImageKey {
        changed,
        identity,
        modified: match metadata
            .modified()
            .map_err(|e| error("read executable cache modification time", e))?
            .duration_since(UNIX_EPOCH)
        {
            Ok(value) => (false, value.as_secs(), value.subsec_nanos()),
            Err(error) => {
                let value = error.duration();
                (true, value.as_secs(), value.subsec_nanos())
            }
        },
        size: metadata.len(),
    })
}
fn cache() -> &'static Mutex<Cache> {
    CACHE.get_or_init(|| Mutex::new(VecDeque::with_capacity(64)))
}
/// Executables larger than this refuse before any content read. The streaming
/// counter also rejects growth beyond the cap during an observation.
const MAX_IMAGE_BYTES: u64 = 512 * 1024 * 1024;

#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
pub(super) fn hash_image(file: std::fs::File, bound: &IpcIoBound) -> IpcNativeResult<Sha256> {
    #[cfg(windows)]
    let (mut file, guarded) = match windows::pin(&file) {
        Some(pin) => (pin, true),
        None => (file, false),
    };
    #[cfg(not(windows))]
    let mut file = file;
    use std::io::Read;
    let before = file
        .metadata()
        .map_err(|e| error("read pinned image metadata", e))?;
    if !before.is_file() || before.len() > MAX_IMAGE_BYTES {
        return Err(refuse(
            IpcNativeErrorCode::Unreadable,
            "peer executable exceeds the 512 MiB regular-file proof bound",
        ));
    }
    bound
        .remaining()
        .map_err(|e| error("executable cache deadline", e))?;
    let stamp = key(&file, &before)?;
    #[cfg(windows)]
    let reusable = guarded && stamp.reusable();
    #[cfg(not(windows))]
    let reusable = true;
    let cached = if reusable {
        let cache = cache().lock().map_err(|_| {
            refuse(
                IpcNativeErrorCode::Unreadable,
                "executable cache poisoned; restart the host",
            )
        })?;
        cache
            .iter()
            .find_map(|(stored, digest)| (stored == &stamp).then_some(*digest))
    } else {
        None
    };
    if let Some(digest) = cached {
        let after = file
            .metadata()
            .map_err(|e| error("reobserve cached executable", e))?;
        bound
            .remaining()
            .map_err(|e| error("cached executable proof deadline", e))?;
        if key(&file, &after)? != stamp {
            return Err(refuse(
                IpcNativeErrorCode::PeerChanged,
                "executable changed during cached proof; rediscover and retry the original key",
            ));
        }
        return Ok(digest);
    }
    let mut read = 0u64;
    let mut hasher = Hasher::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        bound
            .remaining()
            .map_err(|e| error("peer executable proof deadline", e))?;
        let count = file
            .read(&mut buffer)
            .map_err(|e| error("read pinned peer executable", e))?;
        if count == 0 {
            break;
        }
        read += count as u64;
        if read > MAX_IMAGE_BYTES {
            return Err(refuse(
                IpcNativeErrorCode::PeerChanged,
                "peer executable grew beyond proof byte cap",
            ));
        }
        hasher.update(&buffer[..count]);
    }
    bound
        .remaining()
        .map_err(|e| error("finish peer executable proof", e))?;
    let after = file
        .metadata()
        .map_err(|e| error("reobserve pinned image metadata", e))?;
    if read != before.len()
        || !before.is_file()
        || before.len() != after.len()
        || before
            .modified()
            .map_err(|e| error("read pinned image modification clock", e))?
            != after
                .modified()
                .map_err(|e| error("reobserve pinned image modification clock", e))?
    {
        return Err(refuse(
            IpcNativeErrorCode::PeerChanged,
            "executable changed while hashing its native pin",
        ));
    }
    if key(&file, &after)? != stamp {
        return Err(refuse(
            IpcNativeErrorCode::PeerChanged,
            "executable identity changed while hashing; rediscover and retry the original request",
        ));
    }
    let digest = Sha256::from_bytes(hasher.finalize().into());
    if reusable {
        remember(stamp, digest)?;
    }
    Ok(digest)
}

/// Populate only an absent key. An already-observed process-local proof wins
/// over a persisted hint, including a contradictory protected cache entry.
pub(super) fn remember(stamp: ImageKey, digest: Sha256) -> IpcNativeResult<()> {
    if !stamp.reusable() {
        return Ok(());
    }
    let mut cache = cache().lock().map_err(|_| {
        refuse(
            IpcNativeErrorCode::Unreadable,
            "executable cache poisoned; restart the host",
        )
    })?;
    if cache.iter().any(|(stored, _)| *stored == stamp) {
        return Ok(());
    }
    if cache.len() == 64 {
        cache.pop_front();
    }
    cache.push_back((stamp, digest));
    Ok(())
}
