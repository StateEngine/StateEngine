//! Sole-reader observation of retained Windows child output, without reader threads.
use std::{
    fs::File,
    io::{self, Read},
    os::windows::io::{AsRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{Foundation::ERROR_BROKEN_PIPE, System::Pipes::PeekNamedPipe};

/// Own the only reader of a child's anonymous output pipe.
pub struct NativeChildPipe(File);

impl NativeChildPipe {
    /// The handle must be an anonymous child output pipe with no other readers.
    pub fn new(handle: OwnedHandle) -> Self {
        Self(File::from(handle))
    }

    /// `None` means pending, `Some(0)` means EOF, and a positive count is data.
    /// No read is issued until bytes are available on this exclusively owned pipe.
    pub fn read_available(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        if buffer.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty pipe buffer",
            ));
        }
        let handle = self.0.as_raw_handle();
        let mut available = 0;
        // SAFETY: the retained child reader owns this pipe; the only output is
        // initialized and writable. No other operation reads this handle.
        if unsafe {
            PeekNamedPipe(
                handle,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut available,
                ptr::null_mut(),
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                Ok(Some(0))
            } else {
                Err(error)
            };
        }
        if available == 0 {
            return Ok(None);
        }
        let amount = buffer.len().min(available as usize);
        let result = self.0.read(&mut buffer[..amount]);
        match result {
            Ok(count) => Ok(Some(count)),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(None),
            Err(error) if error.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) => Ok(Some(0)),
            Err(error) => Err(error),
        }
    }
}
