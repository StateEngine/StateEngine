//! Recursive native streams share one nonblocking descriptor with the host reactor.
use super::*;
use crate::source_events_macos as stream;
use std::{
    cell::RefCell,
    collections::BTreeMap,
    ffi::OsStr,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::net::UnixDatagram,
    },
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
struct State {
    next: u32,
    registrations: BTreeMap<u32, [u8; 32]>,
    streams: BTreeMap<[u8; 32], stream::Stream>,
}
pub struct NativeSourceWatch {
    receiver: UnixDatagram,
    sender: UnixDatagram,
    pending: Arc<AtomicBool>,
    lost: Arc<AtomicBool>,
    state: RefCell<State>,
}
impl NativeSourceWatch {
    pub fn new() -> io::Result<Self> {
        let (receiver, sender) = UnixDatagram::pair()?;
        receiver.set_nonblocking(true)?;
        sender.set_nonblocking(true)?;
        Ok(Self {
            receiver,
            sender,
            pending: Arc::new(AtomicBool::new(false)),
            lost: Arc::new(AtomicBool::new(false)),
            state: RefCell::new(State {
                next: 0,
                registrations: BTreeMap::new(),
                streams: BTreeMap::new(),
            }),
        })
    }
    /// Arm recursive changes before the first source reconciliation scan.
    pub fn start(&self, root: &NativeSourceRoot) -> io::Result<()> {
        root.check()?;
        let key = root.physical_identity()?;
        let mut state = self.state.borrow_mut();
        if let std::collections::btree_map::Entry::Vacant(slot) = state.streams.entry(key) {
            let stream = stream::Stream::new(
                &root.path,
                stream::Signal {
                    socket: self.sender.try_clone()?,
                    pending: self.pending.clone(),
                    lost: self.lost.clone(),
                },
            )?;
            root.check()?;
            slot.insert(stream);
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
        self.start(root)?;
        let key = root.physical_identity()?;
        let mut state = self.state.borrow_mut();
        if state.registrations.len() >= 1024 {
            return Err(io::Error::other(
                "native source watch registration bound reached",
            ));
        }
        let descriptor = state
            .next
            .checked_add(1)
            .ok_or_else(|| io::Error::other("native source watch identity exhausted"))?;
        if !directory.validate_name()? {
            return Err(changed("watched directory changed during subscription"));
        }
        let identity = directory.revision()?.root_key();
        state.next = descriptor;
        state.registrations.insert(descriptor, key);
        Ok(Some(NativeWatchRegistration {
            descriptor,
            physical_directory: identity,
        }))
    }
    pub fn remove(&self, descriptor: u32) -> io::Result<bool> {
        let mut state = self.state.borrow_mut();
        let Some(key) = state.registrations.remove(&descriptor) else {
            return Ok(false);
        };
        if !state.registrations.values().any(|value| *value == key) {
            state.streams.remove(&key);
        }
        Ok(true)
    }
    pub fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        if !(4096..=32768).contains(&buffer.len()) {
            return Err(invalid("native watch buffer must be 4096..32768 bytes"));
        }
        match self.receiver.recv(buffer) {
            Ok(1) => (),
            Ok(_) => return Err(io::Error::other("native source watch wake was malformed")),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(0),
            Err(error) => return Err(error),
        }
        self.pending.store(false, Ordering::Release);
        buffer[0] = if self.lost.swap(false, Ordering::AcqRel) {
            2
        } else {
            1
        };
        Ok(1)
    }
    /// Recursive streams have no observed per-directory OS allowance. Logical
    /// mappings retain the host's own finite bound; no descriptor is held per map.
    pub fn observed_limit() -> io::Result<u64> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "recursive source watch has no observed per-directory OS limit",
        ))
    }
}
impl AsFd for NativeSourceWatch {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.receiver.as_fd()
    }
}
pub struct NativeWatchEvents<'a> {
    bytes: &'a [u8],
}
impl<'a> NativeWatchEvents<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}
impl<'a> Iterator for NativeWatchEvents<'a> {
    type Item = io::Result<NativeWatchEvent<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        let (&byte, rest) = self.bytes.split_first()?;
        self.bytes = rest;
        let action = match byte {
            1 => NativeWatchAction::Rescan,
            2 => NativeWatchAction::Overflow,
            _ => return Some(Err(invalid("native source watch event is malformed"))),
        };
        Some(Ok(NativeWatchEvent {
            descriptor: None,
            action,
            name: OsStr::new(""),
            directory: true,
            watch_removed: false,
            cookie: 0,
        }))
    }
}
