//! A single short-lived Atlas process, never an agent or provider session.
//! Native custody remains here; the host owns the typed index protocol.
#[cfg(target_os = "linux")]
use std::time::Duration;
use std::{
    io::{self, Read, Write},
    path::Path,
    time::Instant,
};
#[cfg(any(windows, target_os = "macos", test))]
mod stderr;
pub const ENTRY: &str = "--stateengine-private-atlas-cold";
pub const FRAME_BYTES: usize = 65536;
pub const MEMORY_BYTES: u64 = 64_000_000;
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
mod cpu;
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
pub use cpu::current_cpu_time;
// The dedicated worker image maps about 18.5 MiB of virtual address space
// before its parser/SQL allocations, for either CLI feature set. Keep growth
// headroom above the observed 64.03 MB admission requirement, including its
// unchanged 8 MB margin; resident memory remains capped separately at 64 MB.
#[cfg(target_os = "linux")]
pub const ADDRESS_SPACE_BYTES: u64 = 96_000_000;
#[cfg(target_os = "linux")]
mod allocator;
#[cfg(target_os = "linux")]
mod diagnostics;
#[cfg(target_os = "linux")]
pub use allocator::{
    release_pages as release_allocator_pages, reusable_arena_bytes, virtual_bytes,
};
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
pub mod lease;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{AtlasWorker, WorkerChannel};
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{AtlasWorker, WorkerChannel};
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{AtlasWorker, WorkerChannel};

#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
fn acquire_lease() -> io::Result<lease::Lease> {
    lease::Lease::acquire().map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            invalid("previous Atlas child has not been reaped")
        } else {
            error
        }
    })
}

/// Measurement used before entering a native parser allocation. It matches
/// the platform's cold limit; resident observation is named as such on macOS.
pub fn memory_usage() -> io::Result<(u64, &'static str)> {
    #[cfg(target_os = "linux")]
    {
        virtual_bytes().map(|bytes| (bytes, "virtual address space"))
    }
    #[cfg(windows)]
    {
        windows::committed_bytes().map(|bytes| (bytes, "committed memory"))
    }
    #[cfg(target_os = "macos")]
    {
        macos::footprint_bytes().map(|bytes| (bytes, "observed peak physical footprint"))
    }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native Atlas memory measurement unavailable",
        ))
    }
}
#[cfg(any(windows, target_os = "macos"))]
pub fn release_allocator_pages() {
    // These native allocators have no glibc arena to trim. Freed allocations
    // retain their platform semantics; native memory limits remain enforced.
}

pub fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > FRAME_BYTES {
        return Err(invalid("Atlas frame exceeds 65536 bytes"));
    }
    writer.write_all(&(bytes.len() as u32).to_le_bytes())?;
    writer.write_all(bytes)
}
pub fn read_frame(reader: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length > FRAME_BYTES {
        return Err(invalid("Atlas frame exceeds 65536 bytes"));
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}
#[cfg(any(target_os = "linux", windows, target_os = "macos"))]
fn remaining(deadline: Instant) -> io::Result<std::time::Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Atlas worker deadline elapsed"))
}
#[cfg(any(windows, target_os = "macos"))]
fn peer_error(error: crate::native_ipc::IpcNativeError) -> io::Error {
    let kind = if error.code == crate::native_ipc::IpcNativeErrorCode::TimedOut {
        io::ErrorKind::TimedOut
    } else {
        io::ErrorKind::Other
    };
    io::Error::new(kind, error)
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
pub struct AtlasWorker;
#[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
impl AtlasWorker {
    pub fn spawn(_image: &Path, _payload: &[u8], _deadline: Instant) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native Atlas cold containment is unavailable on this platform",
        ))
    }
}
