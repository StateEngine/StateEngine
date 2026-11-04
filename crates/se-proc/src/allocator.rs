//! glibc's process-wide free-page reclaim, without changing allocation policy.

/// Release unused heap pages across all glibc arenas. This is thread-safe and
/// leaves live allocations valid. False means glibc released no pages, not an
/// error or a claim about the process's remaining resident memory.
pub fn reclaim_unused_allocator_pages() -> bool {
    // SAFETY: malloc_trim is glibc's thread-safe, argument-only allocator API;
    // zero requests no retained padding and does not access caller-owned memory.
    unsafe { libc::malloc_trim(0) != 0 }
}
