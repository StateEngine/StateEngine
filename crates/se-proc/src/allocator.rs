//! glibc's process-wide free-page reclaim, without changing allocation policy.

/// Release unused heap pages across all glibc arenas. This is thread-safe and
/// leaves live allocations valid. False means glibc released no pages, not an
/// error or a claim about the process's remaining resident memory.
pub fn reclaim_unused_allocator_pages() -> bool {
    // SAFETY: malloc_trim is glibc's thread-safe, argument-only allocator API;
    // zero requests no retained padding and does not access caller-owned memory.
    unsafe { libc::malloc_trim(0) != 0 }
}

/// The release rule, shared by the function and its tests so the test cannot
/// drift from the rule it checks: a named file mapping whose permission
/// string is the executable's primary read-only segment (offset 0) or an
/// executable code mapping.
fn eligible(perms: &str, offset: &str, path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('[')
        && ((perms == "r--p" && offset == "00000000") || perms == "r-xp")
}

struct Vma {
    bounds: String,
    perms: String,
    offset: String,
    path: String,
    anonymous_kib: u64,
    private_dirty_kib: u64,
}

fn parse_smaps(smaps: &str) -> Vec<Vma> {
    let mut vmas = Vec::new();
    for line in smaps.lines() {
        let head = line.split(' ').next().unwrap_or("");
        if head.len() > 8 && head.contains('-') {
            let mut fields = line.splitn(6, ' ');
            if let (Some(bounds), Some(perms), Some(offset), Some(_), Some(_), Some(path)) = (
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
            ) {
                vmas.push(Vma {
                    bounds: bounds.to_owned(),
                    perms: perms.to_owned(),
                    offset: offset.to_owned(),
                    path: path.trim().to_owned(),
                    anonymous_kib: 0,
                    private_dirty_kib: 0,
                });
            }
        } else if let Some(vma) = vmas.last_mut() {
            let counter = |prefix: &str| {
                line.strip_prefix(prefix)
                    .and_then(|rest| rest.split_whitespace().next())
                    .and_then(|value| value.parse::<u64>().ok())
            };
            if let Some(value) = counter("Anonymous:") {
                vma.anonymous_kib = value;
            } else if let Some(value) = counter("Private_Dirty:") {
                vma.private_dirty_kib = value;
            }
        }
    }
    vmas
}

/// Release the process's own read-only mapped file pages: the primary `r--p`
/// mapping (offset 0) and the `r-xp` code mappings of the executable and its
/// shared libraries.
///
/// A mapping is released only when its smaps counters prove that every
/// resident page is clean file content: `Anonymous` and `Private_Dirty` are
/// both zero. A `MAP_PRIVATE` mapping can show `r-xp`, or `r--p` at offset 0,
/// yet still hold copy-on-write pages that differ from the file: a library
/// with text relocations, code patched through a temporary mprotect, a
/// debugger breakpoint. `MADV_DONTNEED` on such a mapping would silently swap
/// the patched bytes back to the file bytes, so the selection verifies the
/// pages instead of trusting the permission string. The absence of a write
/// bit keeps the set closed: a page cannot become anonymous later without a
/// permission change, which is a new mapping decision.
///
/// Released pages are clean file content, so `MADV_DONTNEED` writes nothing
/// back to the file and the next access re-faults the same bytes from the
/// page cache. Each file's RELRO and data mappings are left alone because
/// they can hold process-private relocation state.
///
/// Without this, an idle host keeps tens of MiB of demand-paged code resident
/// until the kernel's own reclaim happens to run, which on a loaded box is
/// later than the idle measurement window. False means no eligible page was
/// released, not an error or a claim about the remaining resident memory.
pub fn release_read_only_mapped_pages() -> bool {
    let Ok(smaps) = std::fs::read_to_string("/proc/self/smaps") else {
        return false;
    };
    parse_smaps(&smaps)
        .into_iter()
        .filter(|vma| {
            eligible(&vma.perms, &vma.offset, &vma.path)
                && vma.anonymous_kib == 0
                && vma.private_dirty_kib == 0
        })
        .any(|vma| release_vma(&vma))
}

fn release_vma(vma: &Vma) -> bool {
    let Some((lo, hi)) = vma.bounds.split_once('-') else {
        return false;
    };
    let (Ok(lo), Ok(hi)) = (u64::from_str_radix(lo, 16), u64::from_str_radix(hi, 16)) else {
        return false;
    };
    let len = hi.saturating_sub(lo) as usize;
    if len == 0 {
        return false;
    }
    // SAFETY: the range is this process's own live mapping, read verbatim
    // from /proc/self/smaps. The selection admits only named read-only file
    // mappings (no write bit, so the page set is closed) whose counters show
    // zero Anonymous and zero Private_Dirty, so every resident page is clean
    // file content; MADV_DONTNEED discards exactly those pages, writes
    // nothing to the file, and never touches caller memory.
    let rc = unsafe { libc::madvise(lo as *mut _, len, libc::MADV_DONTNEED) };
    rc == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Resident kilobytes inside mappings the release rule addresses, read
    /// from the same smaps the release trusts.
    fn eligible_resident_kilobytes() -> u64 {
        let smaps = std::fs::read_to_string("/proc/self/smaps")
            .unwrap_or_else(|_| panic!("own smaps unreadable"));
        let mut total = 0;
        let mut current = false;
        for line in smaps.lines() {
            let head = line.split(' ').next().unwrap_or("");
            if head.len() > 8 && head.contains('-') {
                let mut fields = line.splitn(6, ' ');
                current = matches!(
                    (
                        fields.next(),
                        fields.next(),
                        fields.next(),
                        fields.next(),
                        fields.next(),
                        fields.next()
                    ),
                    (Some(_), Some(perms), Some(offset), Some(_), Some(_), Some(path))
                        if eligible(perms, offset, path.trim())
                );
            } else if current && let Some(rest) = line.strip_prefix("Rss:") {
                total += rest
                    .split_whitespace()
                    .next()
                    .and_then(|value| value.parse::<u64>().ok())
                    .unwrap_or(0);
            }
        }
        total
    }

    #[test]
    fn eligibility_predicate_matches_the_rule() {
        assert!(eligible("r--p", "00000000", "/usr/bin/se"));
        assert!(eligible(
            "r-xp",
            "00c81000",
            "/usr/lib/x86_64-linux-gnu/libc.so.6"
        ));
        assert!(!eligible("r-xp", "00000000", "[vdso]"));
        assert!(!eligible("r--p", "0024db000", "/usr/bin/se"));
        assert!(!eligible("rw-p", "0025ae000", "/usr/bin/se"));
        assert!(!eligible("r--p", "00000000", ""));
    }

    #[test]
    fn releases_read_only_mapped_pages() {
        let before = eligible_resident_kilobytes();
        assert!(
            before > 0,
            "the test process must hold resident read-only file pages"
        );
        assert!(release_read_only_mapped_pages());
        let after = eligible_resident_kilobytes();
        assert!(
            after < before,
            "eligible resident kilobytes should fall: before {before}, after {after}"
        );
    }

    /// Write a page of a private file mapping, make the mapping read-only
    /// again, and prove the release left the written bytes in place. Such a
    /// mapping shows `r--p` at offset 0 with a nonzero `Anonymous` counter, so
    /// the release must skip it; had it been madvised, the bytes would have
    /// silently reverted to the file content (0x5a) instead of the sentinel.
    #[test]
    fn skips_cow_pages_in_read_only_mappings() {
        let file =
            std::env::temp_dir().join(format!("se-proc-cow-test-{}.bin", std::process::id()));
        const PAGE: usize = 4096;
        std::fs::write(&file, vec![0x5au8; PAGE]).unwrap_or_else(|_| panic!("write test file"));
        let name = std::ffi::CString::new(file.to_string_lossy().into_owned())
            .unwrap_or_else(|_| panic!("no NUL in path"));
        // SAFETY: the path is a valid C string for open, and the result is
        // checked before use.
        let fd = unsafe { libc::open(name.as_ptr(), libc::O_RDWR) };
        assert!(fd >= 0, "open test file");
        // SAFETY: the mapping covers one file page; every access below stays
        // inside it, and it is unmapped and closed at the end of the test.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE,
                fd,
                0,
            )
        };
        assert!(raw != libc::MAP_FAILED, "mmap test file");
        let ptr = raw as *mut u8;
        // SAFETY: every write targets the mapped page established above.
        unsafe {
            (0..PAGE).for_each(|i| *ptr.add(i) = 0xa5);
            assert_eq!(
                libc::mprotect(raw, PAGE, libc::PROT_READ),
                0,
                "mprotect read-only"
            );
        }
        assert!(
            release_read_only_mapped_pages(),
            "clean code pages still released"
        );
        let mut buf = [0u8; PAGE];
        // SAFETY: the copy reads the mapped page into a same-sized buffer.
        unsafe {
            std::ptr::copy_nonoverlapping(ptr, buf.as_mut_ptr(), PAGE);
        }
        assert_eq!(
            buf.to_vec(),
            vec![0xa5u8; PAGE],
            "COW pages must survive the release"
        );
        // SAFETY: the mapping and descriptor were opened by this test.
        unsafe {
            libc::munmap(raw, PAGE);
            libc::close(fd);
        }
        std::fs::remove_file(&file).ok();
    }

    /// The smaps read plus parse plus madvise is a once-per-reclaim cost;
    /// keep it small enough to stay invisible in the idle CPU budget.
    #[test]
    fn smaps_verified_release_stays_small() {
        release_read_only_mapped_pages();
        let iterations = 1000;
        let start = std::time::Instant::now();
        for _ in 0..iterations {
            release_read_only_mapped_pages();
        }
        let per_call_us = start.elapsed().as_nanos() as u64 / iterations as u64 / 1000;
        println!(
            "smaps-verified release averaged {per_call_us} us per call over {iterations} calls"
        );
        assert!(
            per_call_us < 5000,
            "one reclaim must stay under 5 ms, measured {per_call_us} us"
        );
    }
}
