//! Bounded executable proofs. Unix reuse requires stable native file identity,
//! modification/change times and size. Windows reuse requires a positive journal
//! revision bound to its journal instance while a native handle excludes writers.
//! Unsupported revisions fall back to reading the bytes. A pathname is never a cache identity.
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
mod windows {
    //! A qualified file revision binds writer exclusion to its journal instance.
    use std::{
        fs::File,
        mem::size_of,
        os::windows::io::{AsRawHandle, FromRawHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_NAME_OPENED, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
            GetFinalPathNameByHandleW, OPEN_EXISTING, ReOpenFile, VOLUME_NAME_GUID,
        },
        System::{
            IO::DeviceIoControl,
            Ioctl::{FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_FILE_USN_DATA, USN_JOURNAL_DATA_V0},
        },
    };

    #[repr(align(8))]
    struct RecordBuffer([u8; 4096]);

    /// Reopen the exact retained file object, never its possibly replaced pathname.
    /// Denying write sharing excludes a live writer whose repeated writes may share
    /// one journal record. Failure leaves the caller on its bounded full-hash path.
    pub(super) fn pin(file: &File) -> Option<File> {
        // SAFETY: borrowed live file handle and documented read/share flags. A new
        // native handle is returned on success; no ownership of the input transfers.
        let raw = unsafe {
            ReOpenFile(
                file.as_raw_handle(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_DELETE,
                0,
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return None;
        }
        // SAFETY: successful ReOpenFile returned a new uniquely owned native handle.
        Some(unsafe { File::from_raw_handle(raw) })
    }

    /// Qualify every key capture, including hint publication outside hash_image.
    /// A full hash performed while a writer lives must not publish that writer's
    /// coalesced revision as reusable. Zero and unsupported journals also miss.
    pub(super) fn revision(file: &File) -> Option<(i64, u64)> {
        let pin = pin(file)?;
        let volume = volume(&pin)?;
        let before = journal(&volume)?;
        let mut output = RecordBuffer([0; 4096]);
        let mut returned = 0;
        // SAFETY: retained file handle, no input/overlapped operation, and a writable
        // aligned bounded byte buffer whose exact size accompanies its pointer.
        if unsafe {
            DeviceIoControl(
                pin.as_raw_handle(),
                FSCTL_READ_FILE_USN_DATA,
                ptr::null(),
                0,
                output.0.as_mut_ptr().cast(),
                output.0.len() as u32,
                &mut returned,
                ptr::null_mut(),
            )
        } == 0
        {
            return None;
        }
        let bytes = output.0.get(..returned as usize)?;
        let length = u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
        let major = u16::from_le_bytes(bytes.get(4..6)?.try_into().ok()?);
        let offset = match major {
            2 => 24,
            3 => 40,
            _ => return None,
        };
        if length > bytes.len() || length < offset + 8 {
            return None;
        }
        let revision = i64::from_le_bytes(bytes.get(offset..offset + 8)?.try_into().ok()?);
        let after = journal(&volume)?;
        (revision > 0
            && before.UsnJournalID != 0
            && before.UsnJournalID == after.UsnJournalID
            && revision >= before.LowestValidUsn
            && revision >= after.LowestValidUsn
            && revision < after.NextUsn)
            .then_some((revision, after.UsnJournalID))
    }

    /// Resolve the volume from the retained file, without following its pathname or
    /// a mutable drive letter. Unsupported namespaces and unavailable access miss.
    fn volume(file: &File) -> Option<File> {
        let mut path = vec![0u16; 32768];
        // SAFETY: retained file handle, bounded writable UTF-16 buffer.
        let length = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                path.as_mut_ptr(),
                path.len() as u32,
                FILE_NAME_OPENED | VOLUME_NAME_GUID,
            )
        } as usize;
        if length == 0 || length >= path.len() {
            return None;
        }
        let path = String::from_utf16(&path[..length]).ok()?;
        let (guid, _) = path.strip_prefix(r"\\?\Volume{")?.split_once("}\\")?;
        // No trailing slash: open the volume itself, not its root directory.
        let name: Vec<u16> = format!(r"\\?\Volume{{{guid}}}")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        // SAFETY: validated NUL-terminated native volume name; read-only access
        // for journal queries, documented sharing and no mutation or ownership transfer.
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return None;
        }
        // SAFETY: successful CreateFileW returned a new uniquely owned handle.
        Some(unsafe { File::from_raw_handle(raw) })
    }

    fn journal(volume: &File) -> Option<USN_JOURNAL_DATA_V0> {
        let mut data = USN_JOURNAL_DATA_V0::default();
        let mut returned = 0;
        // SAFETY: retained volume handle, initialized aligned native output with its
        // exact capacity, no input and a synchronous operation.
        let succeeded = unsafe {
            DeviceIoControl(
                volume.as_raw_handle(),
                FSCTL_QUERY_USN_JOURNAL,
                ptr::null(),
                0,
                (&mut data as *mut USN_JOURNAL_DATA_V0).cast(),
                size_of::<USN_JOURNAL_DATA_V0>() as u32,
                &mut returned,
                ptr::null_mut(),
            )
        };
        (succeeded != 0 && returned as usize == size_of::<USN_JOURNAL_DATA_V0>()).then_some(data)
    }
}
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
