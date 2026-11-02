use super::identity::*;
use crate::runtime::notify::Hub;
use crate::support::*;
use crate::*;
use std::{
    collections::HashMap,
    ptr,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use windows_sys::Win32::{
    Foundation::*,
    System::{IO::*, Threading::INFINITE},
};

/// Completion addresses remain opaque until the owning target matches them to
/// its retained requests. The collector never dereferences an arbitrary packet.
pub(super) trait CompletionTarget: Send + Sync {
    fn completed(&self, address: usize, bytes: u32, status: u32);
    fn shutdown(&self);
    fn drained(&self) -> bool;
}
#[derive(Clone)]
enum Target {
    Job(Weak<Hub>),
    Io(Arc<dyn CompletionTarget>),
}
type Targets = Mutex<HashMap<usize, Target>>;
pub(super) struct Collector {
    pub handle: Arc<Handle>,
    slots: Arc<Targets>,
    next: AtomicUsize,
    closing: Arc<AtomicBool>,
}
pub(super) struct Registration {
    pub key: usize,
    slots: Weak<Targets>,
}
impl Drop for Registration {
    fn drop(&mut self) {
        if let Some(slots) = self.slots.upgrade() {
            let removed = slots
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(&self.key);
            drop(removed);
        }
    }
}
#[derive(Clone)]
pub(super) struct CompletionQueue {
    pub handle: Arc<Handle>,
    pub key: usize,
    slots: Weak<Targets>,
}
impl CompletionQueue {
    pub fn nudge(&self) {
        // SAFETY: retained IOCP; a null OVERLAPPED is our coalesced control nudge.
        unsafe {
            PostQueuedCompletionStatus(self.handle.0, 0, self.key, ptr::null());
        }
    }
    pub fn unregister(&self) {
        if let Some(slots) = self.slots.upgrade() {
            let removed = slots
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .remove(&self.key);
            drop(removed);
        }
    }
}
impl Collector {
    pub fn new() -> ProcResult<Self> {
        // SAFETY: creates this host's one unassociated completion port.
        let handle = Arc::new(Handle::new(
            unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, ptr::null_mut(), 0, 1) },
            "CreateIoCompletionPort",
        )?);
        let slots: Arc<Targets> = Arc::new(Mutex::new(HashMap::new()));
        let closing = Arc::new(AtomicBool::new(false));
        let (port, lookup, shutdown) = (handle.clone(), slots.clone(), closing.clone());
        std::thread::Builder::new()
            .name("se-native-collector".into())
            .spawn(move || {
                loop {
                    let (mut bytes, mut key, mut overlapped) = (0, 0, ptr::null_mut());
                    // SAFETY: retained IOCP and writable outputs; the sole native waiter.
                    let ok = unsafe {
                        GetQueuedCompletionStatus(
                            port.0,
                            &mut bytes,
                            &mut key,
                            &mut overlapped,
                            INFINITE,
                        )
                    };
                    // Read the native status immediately, before locks or callbacks.
                    // SAFETY: thread-local status from the immediately preceding call.
                    let status = if ok == 0 {
                        // SAFETY: immediate thread-local status from the native call.
                        unsafe { GetLastError() }
                    } else {
                        ERROR_SUCCESS
                    };
                    let target = lookup
                        .lock()
                        .unwrap_or_else(|error| error.into_inner())
                        .get(&key)
                        .cloned();
                    match target {
                        Some(Target::Job(hub)) => {
                            if let Some(hub) = hub.upgrade() {
                                hub.fire(if ok == 0 {
                                    ExitNoticeKind::MonitorFailed
                                } else {
                                    ExitNoticeKind::ScopeChanged
                                });
                            }
                        }
                        Some(Target::Io(port)) => {
                            port.completed(overlapped as usize, bytes, status)
                        }
                        None => (),
                    }
                    if shutdown.load(Ordering::Acquire) {
                        // Clone targets and drop the registry lock before calling them.
                        let ios = {
                            let slots = lookup.lock().unwrap_or_else(|error| error.into_inner());
                            slots
                                .iter()
                                .filter_map(|(key, target)| {
                                    if let Target::Io(io) = target {
                                        Some((*key, io.clone()))
                                    } else {
                                        None
                                    }
                                })
                                .collect::<Vec<_>>()
                        };
                        for (key, io) in &ios {
                            io.shutdown();
                            if io.drained() {
                                let removed = lookup
                                    .lock()
                                    .unwrap_or_else(|error| error.into_inner())
                                    .remove(key);
                                drop(removed);
                            }
                        }
                        if ios.iter().all(|(_, io)| io.drained()) {
                            break;
                        }
                    }
                }
            })
            .map_err(|e| {
                native(
                    ProcErrorCode::ContainmentUnavailable,
                    "start native collector",
                    e,
                )
            })?;
        Ok(Self {
            handle,
            slots,
            next: AtomicUsize::new(1),
            closing,
        })
    }
    fn next_key(&self) -> ProcResult<usize> {
        if self.closing.load(Ordering::Acquire) {
            return Err(input("IOCP", "collector is shutting down"));
        }
        self.next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| capacity("IOCP keys", usize::MAX as u64))
    }
    pub fn register(&self, hub: &Arc<Hub>) -> ProcResult<Registration> {
        let key = self.next_key()?;
        self.slots
            .lock()
            .map_err(|_| input("IOCP", "notification registry poisoned"))?
            .insert(key, Target::Job(Arc::downgrade(hub)));
        Ok(Registration {
            key,
            slots: Arc::downgrade(&self.slots),
        })
    }
    pub fn register_io(&self, target: Arc<dyn CompletionTarget>) -> ProcResult<CompletionQueue> {
        let key = self.next_key()?;
        self.slots
            .lock()
            .map_err(|_| input("IOCP", "notification registry poisoned"))?
            .insert(key, Target::Io(target));
        Ok(CompletionQueue {
            handle: self.handle.clone(),
            key,
            slots: Arc::downgrade(&self.slots),
        })
    }
}
impl Drop for Collector {
    fn drop(&mut self) {
        self.closing.store(true, Ordering::Release);
        // SAFETY: wake the retained collector; it cancels/drains every port before
        // exit. Pending OVERLAPPED storage is never freed by this destructor.
        unsafe {
            PostQueuedCompletionStatus(self.handle.0, 0, 0, ptr::null());
        }
    }
}
