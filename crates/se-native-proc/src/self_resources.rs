//! Linux counters for the calling host only; children are never sampled.
use crate::{
    ProcErrorCode, ProcResult,
    support::{input, native},
};
use std::{
    fs::File,
    io::{self, Read},
};

pub struct SelfResources {
    pub voluntary_switches: u64,
    pub involuntary_switches: u64,
    pub cpu_user_us: u64,
    pub cpu_system_us: u64,
    pub rss_bytes: u64,
}

pub fn observe_self_resources() -> ProcResult<SelfResources> {
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    // SAFETY: SELF selects this process including its threads, with one writable
    // rusage output; success initializes the complete native structure.
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } != 0 {
        return Err(native(
            ProcErrorCode::IdentityUnreadable,
            "getrusage(RUSAGE_SELF)",
            io::Error::last_os_error(),
        ));
    }
    // SAFETY: checked successful native initialization above.
    let usage = unsafe { usage.assume_init() };
    let nonnegative = |value: libc::c_long| {
        u64::try_from(value).map_err(|_| input("host self resources", "negative native counter"))
    };
    let micros = |value: libc::timeval| -> ProcResult<u64> {
        let fraction = nonnegative(value.tv_usec)?;
        if fraction >= 1_000_000 {
            return Err(input(
                "host self resources",
                "invalid native microsecond fraction",
            ));
        }
        nonnegative(value.tv_sec)?
            .checked_mul(1_000_000)
            .and_then(|seconds| seconds.checked_add(fraction))
            .ok_or_else(|| input("host self resources", "native CPU counter overflow"))
    };
    let mut statm = Vec::with_capacity(513);
    File::open("/proc/self/statm")
        .and_then(|file| file.take(513).read_to_end(&mut statm))
        .map_err(|error| {
            native(
                ProcErrorCode::IdentityUnreadable,
                "read /proc/self/statm",
                error,
            )
        })?;
    if statm.len() > 512 {
        return Err(input("host self resources", "statm exceeds 512 bytes"));
    }
    let fields = std::str::from_utf8(&statm)
        .map_err(|_| input("host self resources", "statm is not ASCII"))?
        .split_ascii_whitespace()
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| input("host self resources", "invalid statm counter"))?;
    if fields.len() != 7 {
        return Err(input("host self resources", "incomplete statm counters"));
    }
    // SAFETY: immutable native page-size query; no assumed page granularity.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page = u64::try_from(page)
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| input("host self resources", "native page size unavailable"))?;
    let rss_bytes = fields[1]
        .checked_mul(page)
        .ok_or_else(|| input("host self resources", "RSS counter overflow"))?;
    Ok(SelfResources {
        voluntary_switches: nonnegative(usage.ru_nvcsw)?,
        involuntary_switches: nonnegative(usage.ru_nivcsw)?,
        cpu_user_us: micros(usage.ru_utime)?,
        cpu_system_us: micros(usage.ru_stime)?,
        rss_bytes,
    })
}
