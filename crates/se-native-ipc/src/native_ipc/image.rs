//! Bounded executable proofs. Unix reuse requires stable native file identity,
//! modification/change times and size. Persistent Windows reuse requires a positive
//! journal revision bound to its instance while a native handle excludes writers.
//! Unsupported revisions read the bytes once per continuously writer-excluded
//! process-local file pin. A pathname is never a cache identity.
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
    // Unix ctime/nanoseconds, or Windows USN/journal-ID bits. Preserve the
    // two-integer wire shape so older readers can decode and miss this hint.
    // Windows tag 0 was a restorable clock; tag 1 lacked a journal instance.
    #[serde(default)]
    changed: Option<(i64, i64)>,
}
#[cfg(windows)]
use crate::native_file_revision as windows;

impl ImageKey {
    pub(super) fn reusable(&self) -> bool {
        #[cfg(windows)]
        {
            // Journal IDs are opaque bits; reserve both earlier unqualified tags.
            matches!(self.changed, Some((revision, journal))
                if revision > 0 && !matches!(journal, 0 | 1))
        }
        #[cfg(not(windows))]
        {
            true
        }
    }
}
// Never retain open file handles in the global cache; on Windows a pinned
// handle with write-sharing denied blocks upgrades, renames, and uninstalls.
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
        let id = se_native_path::windows::file::file_id(file)
            .map_err(|e| error("read executable cache file identity", e))?;
        [id.volume.to_be_bytes().as_slice(), &id.index].concat()
    };
    #[cfg(unix)]
    let changed = {
        use std::os::unix::fs::MetadataExt;
        Some((metadata.ctime(), metadata.ctime_nsec()))
    };
    #[cfg(windows)]
    let revision = windows::revision(file);
    #[cfg(windows)]
    let changed = revision.map(|(usn, journal)| (usn, i64::from_le_bytes(journal.to_le_bytes())));
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

pub(super) fn hash_image(file: std::fs::File, bound: &IpcIoBound) -> IpcNativeResult<Sha256> {
    #[cfg(windows)]
    let (mut file, guarded) = match windows::pin(&file) {
        Some(pin) => (pin, true),
        None => (file, false),
    };
    #[cfg(not(windows))]
    let mut file = file;
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
    // The current pin overlaps any retained cache pin, preserving exclusion
    // even if another thread evicts that entry after the lookup.
    #[cfg(windows)]
    let reusable = guarded;
    #[cfg(not(windows))]
    let reusable = true;
    let hit = if reusable { cached(&stamp)? } else { None };
    if let Some(digest) = hit {
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
    let (read, digest) = read_content(&mut file, bound)?;
    verify_unchanged(&file, &before, read, &stamp, bound)?;
    if reusable && stamp.reusable() {
        remember(stamp, digest)?;
    }
    Ok(digest)
}
/// A reusable key's cached digest.
fn cached(stamp: &ImageKey) -> IpcNativeResult<Option<Sha256>> {
    if !stamp.reusable() {
        return Ok(None);
    }
    let cache = cache().lock().map_err(|_| {
        refuse(
            IpcNativeErrorCode::Unreadable,
            "executable cache poisoned; restart the host",
        )
    })?;
    Ok(cache
        .iter()
        .find_map(|(stored, digest)| (stored == stamp).then_some(*digest)))
}
/// Stream the pinned file under the original deadline and byte cap.
fn read_content(file: &mut File, bound: &IpcIoBound) -> IpcNativeResult<(u64, Sha256)> {
    use std::io::Read;
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
    Ok((read, Sha256::from_bytes(hasher.finalize().into())))
}
/// The exact byte count, size, modification clock and native key must match
/// the observation taken before the read.
fn verify_unchanged(
    file: &File,
    before: &std::fs::Metadata,
    read: u64,
    stamp: &ImageKey,
    bound: &IpcIoBound,
) -> IpcNativeResult<()> {
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
    if key(file, &after)? != *stamp {
        return Err(refuse(
            IpcNativeErrorCode::PeerChanged,
            "executable identity changed while hashing; rediscover and retry the original request",
        ));
    }
    Ok(())
}

/// Populate only an absent reusable key. An already-observed process-local
/// proof wins over a persisted hint, including a contradictory cache entry.
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
