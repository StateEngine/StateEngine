//! Operating-system primitives for native path consumers.
#[cfg(unix)]
pub fn effective_user_id() -> libc::uid_t {
    // SAFETY: geteuid observes the current process and has no side effects.
    unsafe { libc::geteuid() }
}
#[cfg(windows)]
pub mod windows;
