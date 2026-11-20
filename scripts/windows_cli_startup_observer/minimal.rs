//! A fresh Rust process with no application initialization.
#[cfg(windows)]
fn micros() -> u64 {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn QueryPerformanceCounter(value: *mut i64) -> i32;
        fn QueryPerformanceFrequency(value: *mut i64) -> i32;
    }
    let (mut counter, mut frequency) = (0_i64, 0_i64);
    // SAFETY: both calls write to valid local integers.
    assert_ne!(unsafe { QueryPerformanceCounter(&mut counter) }, 0);
    assert_ne!(unsafe { QueryPerformanceFrequency(&mut frequency) }, 0);
    ((counter as u128 * 1_000_000) / frequency as u128) as u64
}

#[cfg(unix)]
fn micros() -> u64 {
    #[repr(C)]
    struct Timespec { sec: i64, nsec: i64 }
    unsafe extern "C" { fn clock_gettime(clock: i32, ts: *mut Timespec) -> i32; }
    let mut time = Timespec { sec: 0, nsec: 0 };
    // SAFETY: the system call writes to a valid local timespec.
    assert_eq!(unsafe { clock_gettime(1, &mut time) }, 0);
    time.sec as u64 * 1_000_000 + time.nsec as u64 / 1_000
}
fn main() { println!("{}", micros()); }
