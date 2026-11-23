//! One nonblocking inotify source. Directory subscription uses an already
//! validated no-follow pin; this layer retains no path map or collected events.
//! A consumer may block in [`NativeSourceWatch::wait`] with no timer: an
//! eventfd made on first use of [`NativeSourceWatch::wake_handle`] ends it.
use super::*;
use std::{
    ffi::{CString, OsStr},
    os::{
        fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    sync::{Arc, OnceLock},
};

pub struct NativeSourceWatch(OwnedFd, OnceLock<Arc<OwnedFd>>);
pub struct NativeWatchEvents<'a> {
    bytes: &'a [u8],
}
/// Ends a [`NativeSourceWatch::wait`] from any thread.
#[derive(Clone)]
pub struct NativeWatchWake(Arc<OwnedFd>);
impl NativeWatchWake {
    pub fn wake(&self) -> io::Result<()> {
        let one = 1u64.to_ne_bytes();
        // SAFETY: live eventfd and the 8-byte buffer an eventfd write takes.
        if unsafe { libc::write(self.0.as_raw_fd(), one.as_ptr().cast(), one.len()) } == 8 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        // A full counter already holds a pending wake.
        match error.kind() {
            io::ErrorKind::WouldBlock => Ok(()),
            _ => Err(error),
        }
    }
}
fn owned(fd: libc::c_int) -> io::Result<OwnedFd> {
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the caller passes a successful new descriptor nobody else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}
impl NativeSourceWatch {
    pub fn new() -> io::Result<Self> {
        // SAFETY: fixed supported flags; success returns a new owned descriptor.
        let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
        Ok(Self(owned(fd)?, OnceLock::new()))
    }
    /// A handle that ends [`Self::wait`]. Obtain it before blocking in `wait`
    /// so the eventfd is registered in `poll`.
    pub fn wake_handle(&self) -> io::Result<NativeWatchWake> {
        if let Some(fd) = self.1.get() {
            return Ok(NativeWatchWake(fd.clone()));
        }
        // SAFETY: fixed supported flags; success returns a new owned descriptor.
        let fd = Arc::new(owned(unsafe {
            libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC)
        })?);
        Ok(NativeWatchWake(self.1.get_or_init(|| fd).clone()))
    }
    /// Block, with no timeout, until events are queued or a wake arrives.
    /// The wake is consumed; queued events are left for [`Self::read`].
    pub fn wait(&self) -> io::Result<()> {
        let wake = self.1.get();
        let entry = |fd: libc::c_int| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // A negative descriptor is skipped by poll.
        let mut fds = [
            entry(self.0.as_raw_fd()),
            entry(wake.map_or(-1, |fd| fd.as_raw_fd())),
        ];
        // SAFETY: two initialized entries over live (or skipped) descriptors.
        while unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) } < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        let bad = libc::POLLERR | libc::POLLNVAL | libc::POLLHUP;
        if (fds[0].revents | fds[1].revents) & bad != 0 {
            return Err(io::Error::other("native watch poll descriptor error"));
        }
        if let Some(wake) = wake.filter(|_| fds[1].revents & libc::POLLIN != 0) {
            let mut count = [0u8; 8];
            // SAFETY: live nonblocking eventfd and an 8-byte buffer; the read
            // resets its counter, and a raced empty read is harmless.
            unsafe { libc::read(wake.as_raw_fd(), count.as_mut_ptr().cast(), 8) };
        }
        Ok(())
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
