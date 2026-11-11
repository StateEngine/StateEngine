//! glibc's process-wide free-page reclaim, without changing allocation policy.

/// Release unused heap pages across all glibc arenas. This is thread-safe and
/// leaves live allocations valid. False means glibc released no pages, not an
/// error or a claim about the process's remaining resident memory.
pub fn reclaim_unused_allocator_pages() -> bool {
    // SAFETY: malloc_trim is glibc's thread-safe, argument-only allocator API;
    // zero requests no retained padding and does not access caller-owned memory.
    unsafe { libc::malloc_trim(0) != 0 }
}

/// Release the process's own read-only mapped file pages: the primary `r--p`
/// mapping (offset 0) and the `r-xp` code mappings of the executable and its
/// shared libraries. Both hold clean, immutable file content, so
/// `MADV_DONTNEED` writes nothing back to the file and the next access
/// re-faults the same bytes from the page cache. The RELRO and data mappings
/// of each file are left alone because they can hold process-private
/// relocation state.
///
/// Without this, an idle host keeps tens of MiB of demand-paged code resident
/// until the kernel's own reclaim happens to run, which on a loaded box is
/// later than the idle measurement window. False means no eligible page was
/// released, not an error or a claim about the remaining resident memory.
pub fn release_read_only_mapped_pages() -> bool {
    let Ok(maps) = std::fs::read_to_string("/proc/self/maps") else {
        return false;
    };
    let mut released = false;
    for line in maps.lines() {
        let mut fields = line.splitn(6, ' ');
        let (Some(bounds), Some(perms), Some(offset), Some(_), Some(_), Some(path)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        let path = path.trim();
        let eligible = !path.is_empty()
            && !path.starts_with('[')
            && ((perms == "r--p" && offset == "00000000") || perms == "r-xp");
        if !eligible {
            continue;
        }
        let Some((lo, hi)) = bounds.split_once('-') else {
            continue;
        };
        let (Ok(lo), Ok(hi)) = (u64::from_str_radix(lo, 16), u64::from_str_radix(hi, 16))
        else {
            continue;
        };
        let len = hi.saturating_sub(lo) as usize;
        if len == 0 {
            continue;
        }
        // SAFETY: the range is this process's own live mapping, read verbatim
        // from /proc/self/maps, and the selection rule admits only read-only
        // file-backed pages; MADV_DONTNEED on them discards clean file pages
        // and never touches caller memory.
        released |= unsafe { libc::madvise(lo as *mut _, len, libc::MADV_DONTNEED) } == 0;
    }
    released
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eligible_resident_kilobytes() -> Option<u64> {
        let smaps = std::fs::read_to_string("/proc/self/smaps").ok()?;
        let mut total = 0;
        let mut eligible = false;
        for line in smaps.lines() {
            let first = line.split(' ').next().unwrap_or("");
            if first.len() > 8 && first.contains('-') {
                let mut fields = line.splitn(6, ' ');
                eligible = matches!(
                    (
                        fields.next(),
                        fields.next(),
                        fields.next(),
                        fields.next(),
                        fields.next(),
                        fields.next()
                    ),
                    (Some(_), Some(perms), Some(offset), Some(_), Some(_), Some(path))
                        if !path.trim().is_empty()
                            && !path.trim().starts_with('[')
                            && ((perms == "r--p" && offset == "00000000")
                                || perms == "r-xp")
                );
            } else if eligible {
                if let Some(rest) = line.strip_prefix("Rss:") {
                    total += rest
                        .split_whitespace()
                        .next()
                        .and_then(|value| value.parse::<u64>().ok())
                        .unwrap_or(0);
                }
            }
        }
        Some(total)
    }

    #[test]
    fn releases_read_only_mapped_pages() {
        let before = eligible_resident_kilobytes().expect("own smaps readable");
        assert!(before > 0, "the test process must hold resident read-only file pages");
        assert!(release_read_only_mapped_pages());
        let after = eligible_resident_kilobytes().expect("own smaps readable");
        assert!(
            after < before,
            "eligible resident kilobytes should fall: before {before}, after {after}"
        );
    }
}
