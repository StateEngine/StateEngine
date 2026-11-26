//! Heap-allocated IOCP slot backed by `UnsafeCell` behind a raw `NonNull` so
//! map moves and host lookups never retag or alias kernel-owned I/O memory.
use std::{
    cell::UnsafeCell,
    ptr::{self, NonNull},
};
use windows_sys::Win32::System::IO::OVERLAPPED;

struct IoStorage {
    overlapped: OVERLAPPED,
    bytes: Vec<u8>,
}

/// Owns a raw heap allocation (`Box::into_raw`) holding `UnsafeCell<IoStorage>`.
/// Never exposes `&IoStorage` or `&mut IoStorage` while kernel I/O is pending.
pub(crate) struct IocpSlot {
    io: NonNull<UnsafeCell<IoStorage>>,
    capacity: usize,
}
// SAFETY: `io` is uniquely owned by `IocpSlot`; callers serialize host access
// under a mutex and never form `&`/`&mut` into `IoStorage` while kernel I/O is pending.
unsafe impl Send for IocpSlot {}

impl Drop for IocpSlot {
    fn drop(&mut self) {
        // SAFETY: `self.io` came from `Box::into_raw` in `IocpSlot::new` and is
        // uniquely owned. Callers only drop `IocpSlot` after kernel I/O completes,
        // is rejected at dispatch, or was never submitted.
        unsafe {
            drop(Box::from_raw(self.io.as_ptr()));
        }
    }
}

impl IocpSlot {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        let capacity = bytes.capacity();
        // SAFETY: zero-initialized OVERLAPPED selects the IOCP with no event handle.
        let overlapped = unsafe { std::mem::zeroed() };
        let raw = Box::into_raw(Box::new(UnsafeCell::new(IoStorage { overlapped, bytes })));
        // SAFETY: `Box::into_raw` always returns a non-null pointer.
        let io = unsafe { NonNull::new_unchecked(raw) };
        Self { io, capacity }
    }

    /// Raw pointer to the pinned `OVERLAPPED` slot without forming `&`/`&mut` to `IoStorage`.
    pub(crate) fn overlapped_ptr(&self) -> *mut OVERLAPPED {
        let slot = UnsafeCell::raw_get(self.io.as_ptr());
        // SAFETY: `slot` points to the live `IoStorage`; `addr_of_mut!` computes
        // the field address without reading or creating a reference.
        unsafe { ptr::addr_of_mut!((*slot).overlapped) }
    }

    pub(crate) fn address(&self) -> usize {
        self.overlapped_ptr() as usize
    }

    /// Returns `(overlapped, data, len)` for submitting kernel I/O.
    ///
    /// # Safety
    /// Caller must hold the owning mutex and must not have submitted kernel I/O
    /// for this slot yet (so no concurrent kernel access exists).
    pub(crate) unsafe fn dispatch_ptrs(&self) -> (*mut OVERLAPPED, *mut u8, u32) {
        let slot = UnsafeCell::raw_get(self.io.as_ptr());
        // SAFETY: caller guarantees no kernel I/O is pending yet; this temporary
        // borrow ends before `ReadFile`/`WriteFile` is invoked.
        let bytes = unsafe { &mut *ptr::addr_of_mut!((*slot).bytes) };
        (
            self.overlapped_ptr(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
        )
    }

    /// Reclaims the owned byte buffer after kernel I/O has completed.
    ///
    /// # Safety
    /// Caller must hold the owning mutex and have verified that kernel I/O is
    /// no longer pending on this slot.
    pub(crate) unsafe fn take_bytes(&mut self) -> Vec<u8> {
        self.capacity = 0;
        let slot = UnsafeCell::raw_get(self.io.as_ptr());
        // SAFETY: caller guarantees kernel I/O is complete and no IOCP packet
        // can access `bytes` again.
        unsafe { std::mem::take(&mut *ptr::addr_of_mut!((*slot).bytes)) }
    }

    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }
}
