use super::identity::*;
use crate::runtime::notify::Hub;
use crate::support::*;
use crate::*;
use std::{
    collections::HashMap,
    ptr,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicUsize, Ordering},
    },
};
use windows_sys::Win32::{
    Foundation::*,
    System::{IO::*, Threading::INFINITE},
};

pub(super) struct Collector {
    pub handle: Arc<Handle>,
    slots: Arc<Mutex<HashMap<usize, Weak<Hub>>>>,
    next: AtomicUsize,
}
pub(super) struct Registration {
    pub key: usize,
    slots: Arc<Mutex<HashMap<usize, Weak<Hub>>>>,
}
impl Drop for Registration {
    fn drop(&mut self) {
        if let Ok(mut slots) = self.slots.lock() {
            slots.remove(&self.key);
        }
    }
}
impl Collector {
    pub fn new() -> ProcResult<Self> {
        // SAFETY: creates a fresh unassociated IOCP, owned by this host's one collector.
        let handle = Arc::new(Handle::new(
            unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, ptr::null_mut(), 0, 1) },
            "CreateIoCompletionPort",
        )?);
        let slots: Arc<Mutex<HashMap<usize, Weak<Hub>>>> = Arc::new(Mutex::new(HashMap::new()));
        let (port, lookup) = (handle.clone(), slots.clone());
        std::thread::Builder::new()
            .name("se-native-collector".into())
            .spawn(move || {
                loop {
                    let mut message = 0;
                    let mut key = 0;
                    let mut overlapped = ptr::null_mut();
                    // SAFETY: valid IOCP and outputs; this is the sole native wait
                    // thread, never a host blocking worker or a per-agent waiter.
                    let ok = unsafe {
                        GetQueuedCompletionStatus(
                            port.0,
                            &mut message,
                            &mut key,
                            &mut overlapped,
                            INFINITE,
                        )
                    };
                    if key == 0 {
                        break;
                    }
                    let hub = lookup
                        .lock()
                        .ok()
                        .and_then(|s| s.get(&key).and_then(Weak::upgrade));
                    if let Some(hub) = hub {
                        hub.fire(if ok == 0 {
                            ExitNoticeKind::MonitorFailed
                        } else {
                            ExitNoticeKind::ScopeChanged
                        });
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
        })
    }
    pub fn register(&self, hub: &Arc<Hub>) -> ProcResult<Registration> {
        let key = self
            .next
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_add(1))
            .map_err(|_| capacity("IOCP keys", usize::MAX as u64))?;
        self.slots
            .lock()
            .map_err(|_| input("IOCP", "notification registry poisoned"))?
            .insert(key, Arc::downgrade(hub));
        Ok(Registration {
            key,
            slots: self.slots.clone(),
        })
    }
}
impl Drop for Collector {
    fn drop(&mut self) {
        // SAFETY: the thread owns its separate Arc to this port until it consumes
        // the shutdown packet. No join blocks the host's async shutdown path.
        unsafe {
            PostQueuedCompletionStatus(self.handle.0, 0, 0, ptr::null());
        }
    }
}
