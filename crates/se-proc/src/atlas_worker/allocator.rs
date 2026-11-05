//! Allocation controls belong only to the validated private cold child.
use std::{
    fs::File,
    io::{self, Read},
};
pub fn configure() -> io::Result<()> {
    #[cfg(target_env = "gnu")]
    {
        // SAFETY: the private entry has one thread and has not created a parser.
        // Fixed mmap/trim thresholds prevent a large previous parse from raising
        // glibc's dynamic threshold and retaining its arena for the entire job.
        let configured = unsafe {
            libc::mallopt(libc::M_MMAP_THRESHOLD, 65536) != 0
                && libc::mallopt(libc::M_TRIM_THRESHOLD, 0) != 0
        };
        if !configured {
            return Err(io::Error::other("cold allocator thresholds refused"));
        }
    }
    Ok(())
}
pub fn release_pages() {
    #[cfg(target_env = "gnu")]
    // SAFETY: called only by the private child between file work quanta; no
    // pointer is transferred or invalidated, and live allocations remain live.
    unsafe {
        libc::malloc_trim(0);
    }
}
/// Already mapped free arena blocks can satisfy later mallocs without growing
/// the address space. Limit the credit so at least 6 MB of the parser margin
/// still consists of unmapped address space, even with fragmented free blocks.
pub fn reusable_arena_bytes() -> u64 {
    #[cfg(target_env = "gnu")]
    {
        // SAFETY: glibc takes its allocator locks and returns a value snapshot;
        // no allocator pointer escapes, and this child has one thread.
        let available = unsafe { libc::mallinfo2().fordblks };
        (available as u64).min(2_000_000)
    }
    #[cfg(not(target_env = "gnu"))]
    0
}
pub fn virtual_bytes() -> io::Result<u64> {
    let mut bytes = [0u8; 256];
    let n = File::open("/proc/self/statm")?.read(&mut bytes)?;
    if n == bytes.len() {
        return Err(io::Error::other("cold statm exceeds bound"));
    }
    let pages: u64 = std::str::from_utf8(&bytes[..n])
        .ok()
        .and_then(|text| text.split_ascii_whitespace().next())
        .and_then(|pages| pages.parse().ok())
        .ok_or_else(|| io::Error::other("cold virtual page count unavailable"))?;
    // SAFETY: immutable system configuration query with no borrowed pointers.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    pages
        .checked_mul(u64::try_from(size).map_err(io::Error::other)?)
        .ok_or_else(|| io::Error::other("cold virtual address count overflow"))
}
