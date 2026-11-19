//! Count native parser allocations and request cancellation at progress checks.
use std::{
    alloc::{Layout, alloc, alloc_zeroed, dealloc, handle_alloc_error, realloc},
    ffi::c_void,
    mem::size_of,
    ptr,
    sync::{
        Once,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

#[repr(C, align(16))]
struct Header {
    size: usize,
}

static INSTALL: Once = Once::new();
static ACTIVE: AtomicBool = AtomicBool::new(false);
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static LIMIT: AtomicUsize = AtomicUsize::new(0);
static EXCEEDED: AtomicBool = AtomicBool::new(false);

pub(super) struct Reservation;
impl Reservation {
    pub fn start(limit: u32) -> Self {
        INSTALL.call_once(|| {
            // SAFETY: Atlas installs this once before its first Tree-sitter use;
            // the parser lease serializes all Atlas parsers and their trees.
            unsafe {
                tree_sitter::set_allocator(Some(malloc), Some(calloc), Some(resize), Some(free))
            };
        });
        LIMIT.store(limit as usize, Ordering::Relaxed);
        EXCEEDED.store(
            CURRENT.load(Ordering::Acquire) > limit as usize,
            Ordering::Relaxed,
        );
        ACTIVE.store(true, Ordering::Release);
        if CURRENT.load(Ordering::Acquire) > limit as usize {
            EXCEEDED.store(true, Ordering::Release);
        }
        Self
    }
    pub fn exceeded(&self) -> bool {
        EXCEEDED.load(Ordering::Acquire)
    }
    pub fn used(&self) -> usize {
        CURRENT.load(Ordering::Acquire)
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        ACTIVE.store(false, Ordering::Release);
    }
}

fn layout(size: usize) -> Layout {
    size.checked_add(size_of::<Header>())
        .and_then(|total| Layout::from_size_align(total, 16).ok())
        .unwrap_or_else(|| std::process::abort())
}
fn charge(size: usize) {
    let current = CURRENT
        .fetch_add(size, Ordering::AcqRel)
        .saturating_add(size);
    if ACTIVE.load(Ordering::Acquire) && current > LIMIT.load(Ordering::Acquire) {
        EXCEEDED.store(true, Ordering::Release);
    }
}

unsafe fn allocate(size: usize, zeroed: bool) -> *mut c_void {
    let layout = layout(size);
    // SAFETY: layout is valid; allocation failure follows Tree-sitter's normal abort behavior.
    let raw = unsafe {
        if zeroed {
            alloc_zeroed(layout)
        } else {
            alloc(layout)
        }
    };
    if raw.is_null() {
        handle_alloc_error(layout);
    }
    // SAFETY: the allocation has room and alignment for the header and payload.
    unsafe { raw.cast::<Header>().write(Header { size }) };
    charge(layout.size());
    // SAFETY: payload follows the header within the allocation.
    unsafe { raw.add(size_of::<Header>()).cast() }
}
unsafe extern "C" fn malloc(size: usize) -> *mut c_void {
    // SAFETY: allocate returns a suitably aligned C allocation.
    unsafe { allocate(size, false) }
}
unsafe extern "C" fn calloc(count: usize, size: usize) -> *mut c_void {
    let size = count
        .checked_mul(size)
        .unwrap_or_else(|| std::process::abort());
    // SAFETY: allocate returns a zeroed and suitably aligned C allocation.
    unsafe { allocate(size, true) }
}
unsafe extern "C" fn resize(pointer: *mut c_void, size: usize) -> *mut c_void {
    if pointer.is_null() {
        // SAFETY: null realloc has malloc semantics.
        return unsafe { allocate(size, false) };
    }
    if size == 0 {
        // SAFETY: this pointer came from the same allocator.
        unsafe { free(pointer) };
        return ptr::null_mut();
    }
    // SAFETY: every pointer returned by this allocator follows an initialized header.
    let raw = unsafe { pointer.cast::<u8>().sub(size_of::<Header>()) };
    // SAFETY: header is aligned and initialized.
    let old = unsafe { raw.cast::<Header>().read() };
    let old_layout = layout(old.size);
    let new_layout = layout(size);
    // SAFETY: raw and old_layout identify the live allocation.
    let new_raw = unsafe { realloc(raw, old_layout, new_layout.size()) };
    if new_raw.is_null() {
        handle_alloc_error(new_layout);
    }
    if new_raw != raw {
        // A moved allocation may have held both blocks before the old one was freed.
        charge(new_layout.size());
        CURRENT.fetch_sub(old_layout.size(), Ordering::AcqRel);
    } else {
        CURRENT.fetch_sub(old_layout.size(), Ordering::AcqRel);
        charge(new_layout.size());
    }
    // SAFETY: the resized allocation contains an aligned header.
    unsafe { new_raw.cast::<Header>().write(Header { size }) };
    // SAFETY: payload follows the header within the resized allocation.
    unsafe { new_raw.add(size_of::<Header>()).cast() }
}
unsafe extern "C" fn free(pointer: *mut c_void) {
    if pointer.is_null() {
        return;
    }
    // SAFETY: every pointer returned by this allocator follows an initialized header.
    let raw = unsafe { pointer.cast::<u8>().sub(size_of::<Header>()) };
    // SAFETY: header is aligned and initialized.
    let header = unsafe { raw.cast::<Header>().read() };
    let layout = layout(header.size);
    CURRENT.fetch_sub(layout.size(), Ordering::AcqRel);
    // SAFETY: raw and layout identify the live allocation.
    unsafe { dealloc(raw, layout) };
}
