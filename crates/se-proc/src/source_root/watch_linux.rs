//! One nonblocking inotify source. Directory subscription uses an already
//! validated no-follow pin; this layer retains no path map or collected events.
use super::*;
use std::{
    ffi::{CString, OsStr},
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
};

pub struct NativeSourceWatch(OwnedFd);
/// An owned finite directory stream can survive a host work quantum. Its root
/// and directory pins remain bound; no borrowed source or raw pathname escapes.
pub struct NativeWatchDirectory {
    root: NativeSourceRoot,
    path: String,
    directory: File,
    identity: NativeFileRevision,
    entries: entries::Cursor,
}
impl NativeWatchDirectory {
    pub fn open(root: &NativeSourceRoot, path: &str) -> io::Result<Option<Self>> {
        let Some(pin) = root.open_directory(path)? else {
            return Ok(None);
        };
        let owned_root = NativeSourceRoot {
            path: root.path.clone(),
            directory: root.directory.try_clone()?,
            identity: root.identity.clone(),
        };
        let NativeRootDirectory {
            path,
            directory,
            identity,
            entries,
            ..
        } = pin;
        Ok(Some(Self {
            root: owned_root,
            path,
            directory,
            identity,
            entries,
        }))
    }
    pub fn physical_identity(&self) -> io::Result<[u8; 32]> {
        if !self.validate_name()? {
            return Err(changed("enumerated directory changed"));
        }
        Ok(self.identity.root_key())
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn validate_name(&self) -> io::Result<bool> {
        self.root.check()?;
        let named = if self.path.is_empty() {
            os::open_root(&self.root.path)
        } else {
            os::open_directory(&self.root.directory, &self.path)
        };
        let named = match named {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        let same = self.identity.same_object(&os::revision(&named, true)?)
            && self
                .identity
                .same_object(&os::revision(&self.directory, true)?);
        self.root.check()?;
        Ok(same)
    }
    pub fn next_entry(&mut self) -> io::Result<Option<NativeSourceEntry>> {
        if !self.validate_name()? {
            return Err(changed("enumerated directory changed"));
        }
        let entry = self.entries.next()?;
        if !self.validate_name()? {
            return Err(changed("enumerated directory changed"));
        }
        Ok(entry)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeWatchRegistration {
    pub descriptor: u32,
    pub physical_directory: [u8; 32],
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeWatchAction {
    Changed,
    Removed,
    MovedFrom,
    MovedTo,
    Invalidated,
    Overflow,
}
#[derive(Debug)]
pub struct NativeWatchEvent<'a> {
    pub descriptor: Option<u32>,
    pub action: NativeWatchAction,
    pub name: &'a OsStr,
    pub directory: bool,
    pub watch_removed: bool,
    pub cookie: u32,
}
pub struct NativeWatchEvents<'a> {
    bytes: &'a [u8],
}
impl NativeSourceWatch {
    pub fn new() -> io::Result<Self> {
        // SAFETY: fixed supported flags; success returns a new owned descriptor.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: this is the sole owner of the successful new descriptor.
        Ok(Self(unsafe { OwnedFd::from_raw_fd(fd) }))
    }
    pub fn subscribe(
        &self,
        root: &NativeSourceRoot,
        path: &str,
    ) -> io::Result<Option<NativeWatchRegistration>> {
        let Some(directory) = root.open_directory(path)? else {
            return Ok(None);
        };
        // Only the kernel-owned descriptor spelling is followed here, never a
        // source symlink. Keep its directory pin alive through both checks.
        let target = CString::new(format!("/proc/self/fd/{}", directory.directory.as_raw_fd()))
            .map_err(|_| invalid("native watch descriptor spelling"))?;
        let flags = libc::IN_ONLYDIR
            | libc::IN_MASK_CREATE
            | libc::IN_MODIFY
            | libc::IN_CLOSE_WRITE
            | libc::IN_ATTRIB
            | libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_MOVED_FROM
            | libc::IN_MOVED_TO
            | libc::IN_DELETE_SELF
            | libc::IN_MOVE_SELF
            | libc::IN_UNMOUNT;
        // SAFETY: live inotify descriptor and NUL-terminated spelling of the
        // still-owned directory descriptor. IN_MASK_CREATE cannot alter a peer watch.
        let wd = unsafe { libc::inotify_add_watch(self.0.as_raw_fd(), target.as_ptr(), flags) };
        if wd < 0 {
            return Err(io::Error::last_os_error());
        }
        let descriptor =
            u32::try_from(wd).map_err(|_| invalid("negative native watch descriptor"))?;
        match directory.validate_name() {
            Ok(true) => (),
            other => {
                self.remove(descriptor)?;
                return Err(other
                    .err()
                    .unwrap_or_else(|| changed("watched directory changed during subscription")));
            }
        }
        Ok(Some(NativeWatchRegistration {
            descriptor,
            physical_directory: directory.identity.root_key(),
        }))
    }
    /// False is a native EINVAL: this exact descriptor is already unwatched.
    pub fn remove(&self, descriptor: u32) -> io::Result<bool> {
        let descriptor =
            i32::try_from(descriptor).map_err(|_| invalid("native watch descriptor"))?;
        // SAFETY: the owned instance and checked descriptor identify one watch.
        if unsafe { libc::inotify_rm_watch(self.0.as_raw_fd(), descriptor) } == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINVAL) {
            Ok(false)
        } else {
            Err(error)
        }
    }
    /// One finite read. Zero means EAGAIN, not an empty successful enumeration.
    /// The caller keeps these bytes until every event is handled or a sticky
    /// reconcile replaces it; a failed directory lookup must not discard a tail.
    pub fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        if !(4096..=32768).contains(&buffer.len()) {
            return Err(invalid("native watch buffer must be 4096..32768 bytes"));
        }
        // SAFETY: valid writable buffer, its exact size and a live descriptor.
        let count =
            unsafe { libc::read(self.0.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        if count < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::WouldBlock {
                Ok(0)
            } else {
                Err(error)
            };
        }
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "native watch stream closed",
            ));
        }
        usize::try_from(count).map_err(|_| invalid("native watch byte count"))
    }
    /// Read once per activation. The host labels a conservative fallback on
    /// failure; an unreadable OS limit never masquerades as zero watches.
    pub fn observed_limit() -> io::Result<u64> {
        let file = File::open("/proc/sys/fs/inotify/max_user_watches")?;
        let mut bytes = Vec::new();
        file.take(65).read_to_end(&mut bytes)?;
        if bytes.len() > 64 {
            return Err(invalid("native watch limit exceeds 64 bytes"));
        }
        let value = std::str::from_utf8(&bytes)
            .map_err(|_| invalid("native watch limit encoding"))?
            .trim()
            .parse::<u64>()
            .map_err(|_| invalid("native watch limit is not an integer"))?;
        if value == 0 {
            return Err(invalid("native watch limit is zero"));
        }
        Ok(value)
    }
}
impl AsFd for NativeSourceWatch {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}
impl<'a> NativeWatchEvents<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
    fn decode(&mut self) -> io::Result<NativeWatchEvent<'a>> {
        let header = self
            .bytes
            .get(..16)
            .ok_or_else(|| invalid("short native watch header"))?;
        let number = |at: usize| -> io::Result<u32> {
            Ok(u32::from_ne_bytes(
                header[at..at + 4]
                    .try_into()
                    .map_err(|_| invalid("native watch field"))?,
            ))
        };
        let wd = i32::from_ne_bytes(
            header[..4]
                .try_into()
                .map_err(|_| invalid("native watch descriptor"))?,
        );
        let mask = number(4)?;
        let cookie = number(8)?;
        let length = usize::try_from(number(12)?).map_err(|_| invalid("native watch name size"))?;
        let end = 16usize
            .checked_add(length)
            .ok_or_else(|| invalid("native watch event overflow"))?;
        let name = self
            .bytes
            .get(16..end)
            .ok_or_else(|| invalid("short native watch name"))?;
        let name = if length == 0 {
            name
        } else {
            let zero = name
                .iter()
                .position(|v| *v == 0)
                .ok_or_else(|| invalid("unterminated native watch name"))?;
            if zero > 255 {
                return Err(invalid("native watch name exceeds Linux NAME_MAX"));
            }
            &name[..zero]
        };
        let action = if mask & libc::IN_Q_OVERFLOW != 0 {
            NativeWatchAction::Overflow
        } else if mask
            & (libc::IN_IGNORED | libc::IN_UNMOUNT | libc::IN_DELETE_SELF | libc::IN_MOVE_SELF)
            != 0
        {
            NativeWatchAction::Invalidated
        } else if mask & libc::IN_MOVED_FROM != 0 {
            NativeWatchAction::MovedFrom
        } else if mask & libc::IN_MOVED_TO != 0 {
            NativeWatchAction::MovedTo
        } else if mask & libc::IN_DELETE != 0 {
            NativeWatchAction::Removed
        } else {
            NativeWatchAction::Changed
        };
        let descriptor = if action == NativeWatchAction::Overflow {
            None
        } else {
            Some(
                u32::try_from(wd)
                    .map_err(|_| invalid("negative native watch descriptor without overflow"))?,
            )
        };
        self.bytes = &self.bytes[end..];
        Ok(NativeWatchEvent {
            descriptor,
            action,
            name: OsStr::from_bytes(name),
            directory: mask & libc::IN_ISDIR != 0,
            watch_removed: mask & libc::IN_IGNORED != 0,
            cookie,
        })
    }
}
impl<'a> Iterator for NativeWatchEvents<'a> {
    type Item = io::Result<NativeWatchEvent<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        let result = self.decode();
        if result.is_err() {
            self.bytes = &[];
        }
        Some(result)
    }
}
