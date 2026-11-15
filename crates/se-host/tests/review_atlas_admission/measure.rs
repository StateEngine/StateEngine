//! Native allocator observations retain the platform allocator and its size rounding.
use std::{
    alloc::{GlobalAlloc, Layout, System},
    ffi::c_void,
    sync::atomic::{AtomicUsize, Ordering},
};
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
fn add(bytes: usize) {
    let now = LIVE.fetch_add(bytes, Ordering::SeqCst) + bytes;
    PEAK.fetch_max(now, Ordering::SeqCst);
}
fn sub(bytes: usize) {
    LIVE.fetch_sub(bytes, Ordering::SeqCst);
}
unsafe fn size(pointer: *mut c_void) -> usize {
    if pointer.is_null() {
        0
    } else {
        unsafe { libc::malloc_size(pointer) }
    }
}
struct Observed;
#[global_allocator]
static ALLOCATOR: Observed = Observed;
unsafe impl GlobalAlloc for Observed {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        add(unsafe { size(p.cast()) });
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc_zeroed(layout) };
        add(unsafe { size(p.cast()) });
        p
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        sub(unsafe { size(pointer.cast()) });
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, bytes: usize) -> *mut u8 {
        let old = unsafe { size(pointer.cast()) };
        let next = unsafe { System.realloc(pointer, layout, bytes) };
        if !next.is_null() {
            sub(old);
            add(unsafe { size(next.cast()) });
        }
        next
    }
}
unsafe extern "C" fn tree_alloc(bytes: usize) -> *mut c_void {
    let p = unsafe { libc::malloc(bytes) };
    add(unsafe { size(p) });
    p
}
unsafe extern "C" fn tree_zero(count: usize, bytes: usize) -> *mut c_void {
    let p = unsafe { libc::calloc(count, bytes) };
    add(unsafe { size(p) });
    p
}
unsafe extern "C" fn tree_realloc(pointer: *mut c_void, bytes: usize) -> *mut c_void {
    let old = unsafe { size(pointer) };
    let next = unsafe { libc::realloc(pointer, bytes) };
    if !next.is_null() || bytes == 0 {
        sub(old);
        add(unsafe { size(next) });
    }
    next
}
unsafe extern "C" fn tree_free(pointer: *mut c_void) {
    sub(unsafe { size(pointer) });
    unsafe { libc::free(pointer) };
}
pub fn install() {
    unsafe {
        tree_sitter::set_allocator(
            Some(tree_alloc),
            Some(tree_zero),
            Some(tree_realloc),
            Some(tree_free),
        )
    };
}
pub fn reset() -> usize {
    let live = LIVE.load(Ordering::SeqCst);
    PEAK.store(live, Ordering::SeqCst);
    live
}
pub fn peak() -> usize {
    PEAK.load(Ordering::SeqCst)
}
pub fn zone() -> serde_json::Value {
    let mut stats: libc::malloc_statistics_t = unsafe { std::mem::zeroed() };
    // The native API aggregates all zones when its first argument is null.
    unsafe { libc::malloc_zone_statistics(std::ptr::null_mut(), &mut stats) };
    serde_json::json!({"in_use": stats.size_in_use, "touched_high_water": stats.max_size_in_use, "reserved": stats.size_allocated})
}
