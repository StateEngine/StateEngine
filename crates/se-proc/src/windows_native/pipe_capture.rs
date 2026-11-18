//! Bounded, nonblocking capture of a child process stderr pipe.
use super::{Result, handle, last};
use std::{
    fs::File,
    os::windows::io::{AsRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::ReadFile,
    System::Pipes::{CreatePipe, PeekNamedPipe},
};

const LIMIT: usize = 16 * 1024;
pub(crate) struct PipeCapture {
    read: OwnedHandle,
    bytes: Vec<u8>,
    omitted: usize,
    error: Option<u32>,
}
impl PipeCapture {
    pub fn new() -> Result<(Self, File)> {
        let mut read = ptr::null_mut();
        let mut write = ptr::null_mut();
        // SAFETY: writable outputs; noninheritable handles. The native creator
        // separately duplicates only the writer into its explicit handle list.
        if unsafe { CreatePipe(&mut read, &mut write, ptr::null(), LIMIT as u32) } == 0 {
            return Err(last("create process stderr"));
        }
        let read = handle(read, "own stderr reader")?;
        let write = File::from(handle(write, "own stderr writer")?);
        Ok((
            Self {
                read,
                bytes: Vec::new(),
                omitted: 0,
                error: None,
            },
            write,
        ))
    }
    pub fn drain(&mut self) {
        // Bound work per poll as well as retained memory. The caller repeats
        // this while the helper runs, so a full pipe cannot hide its exit.
        for _ in 0..4 {
            let mut available = 0;
            // SAFETY: retained synchronous pipe reader, writable count output.
            if unsafe {
                PeekNamedPipe(
                    self.read.as_raw_handle(),
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    &mut available,
                    ptr::null_mut(),
                )
            } == 0
            {
                // SAFETY: thread-local result from the immediately preceding API.
                let error = unsafe { GetLastError() };
                if error != ERROR_BROKEN_PIPE {
                    self.error = Some(error);
                }
                break;
            }
            if available == 0 {
                break;
            }
            let mut buffer = [0u8; 4096];
            let mut read = 0;
            let count = available.min(buffer.len() as u32);
            // SAFETY: this is the only reader; peek proved count bytes ready,
            // and the initialized buffer has at least count writable bytes.
            if unsafe {
                ReadFile(
                    self.read.as_raw_handle(),
                    buffer.as_mut_ptr(),
                    count,
                    &mut read,
                    ptr::null_mut(),
                )
            } == 0
            {
                // SAFETY: thread-local result of the immediately preceding read.
                self.error = Some(unsafe { GetLastError() });
                break;
            }
            let keep = (LIMIT - self.bytes.len()).min(read as usize);
            self.bytes.extend_from_slice(&buffer[..keep]);
            self.omitted = self.omitted.saturating_add(read as usize - keep);
        }
    }
    pub fn describe(&self) -> String {
        let mut pending = 0;
        // SAFETY: retained reader and writable count; no bytes are consumed.
        let pending = if unsafe {
            PeekNamedPipe(
                self.read.as_raw_handle(),
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut pending,
                ptr::null_mut(),
            )
        } != 0
        {
            Ok(pending)
        } else {
            // SAFETY: immediately preceding query's thread-local error.
            Err(unsafe { GetLastError() })
        };
        let text = match std::str::from_utf8(&self.bytes) {
            Ok(text) => format!("stderr: {text}"),
            Err(_) => format!("stderr non-UTF-8 bytes: {:?}", self.bytes),
        };
        format!(
            "{text}; discarded bytes: {}; pending bytes or pipe error: {pending:?}; read error: {:?}",
            self.omitted, self.error
        )
    }
}
