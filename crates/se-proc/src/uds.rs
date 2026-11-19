//! A Windows AF_UNIX socket that an asynchronous runtime can own.
//!
//! `tokio` has no Windows implementation of a Unix-domain socket, and the
//! provider's daemon control socket is one on every platform. The `uds_windows`
//! handle registers with `async-io` only if it exposes its socket and asserts
//! that moving it between tasks is safe. Both requirements need `unsafe`, which
//! the workspace forbids everywhere except this crate; it lives here so callers
//! use a safe type and never write the assertion themselves.

#[cfg(windows)]
mod imp {
    use std::io;
    use std::os::windows::io::{AsRawSocket, AsSocket, BorrowedSocket};

    /// The provider's socket handle, owned for as long as this value lives.
    pub struct Registered(uds_windows::UnixStream);

    impl AsSocket for Registered {
        fn as_socket(&self) -> BorrowedSocket<'_> {
            // SAFETY: `self.0` owns the handle for at least as long as this
            // borrow, so it cannot be closed while the borrow is alive.
            unsafe { BorrowedSocket::borrow_raw(self.0.as_raw_socket()) }
        }
    }

    impl io::Read for Registered {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            io::Read::read(&mut self.0, buffer)
        }
    }

    impl io::Write for Registered {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            io::Write::write(&mut self.0, buffer)
        }

        fn flush(&mut self) -> io::Result<()> {
            io::Write::flush(&mut self.0)
        }
    }

    // SAFETY: every read and write is passed straight through to the socket.
    // This type holds no buffer, no pointer into one, and no address-sensitive
    // state, so a move between tasks cannot invalidate an in-flight operation --
    // which is exactly what `IoSafe` asks the implementor to guarantee.
    unsafe impl async_io::IoSafe for Registered {}

    /// A socket registered with the runtime, ready to be driven by any task.
    pub type Socket = tokio_util::compat::Compat<async_io::Async<Registered>>;

    /// Register a connected handle for the runtime, safely.
    ///
    /// The caller performs the blocking connect on its own blocking pool and
    /// hands the handle here; this crate never starts a runtime of its own.
    pub fn registered(stream: uds_windows::UnixStream) -> io::Result<Socket> {
        use tokio_util::compat::FuturesAsyncReadCompatExt;
        async_io::Async::new(Registered(stream)).map(FuturesAsyncReadCompatExt::compat)
    }
}

#[cfg(windows)]
pub use imp::{Socket, registered};
