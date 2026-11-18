//! Owned windowless console and drained terminal transport. Standard-stream
//! redirection and process policy remain the caller's responsibility.
use super::{Error, Result, handle, last};
use std::{
    fs::File,
    io,
    os::windows::io::{AsRawHandle, OwnedHandle},
    ptr, thread,
};
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::{Console::*, Pipes::CreatePipe},
};

pub(crate) struct PseudoConsole {
    console: HPCON,
    // Keep input open without injecting terminal bytes into the protocol.
    _input: OwnedHandle,
    creator_channels: Option<(OwnedHandle, OwnedHandle)>,
    drain: Option<thread::JoinHandle<io::Result<u64>>>,
}

impl PseudoConsole {
    pub fn new() -> Result<Self> {
        let (input_read, input_write) = pipe()?;
        let (output_read, output_write) = pipe()?;
        // File takes the owned reader; failed thread creation closes it too.
        let mut output = File::from(output_read);
        let drain = thread::Builder::new()
            .name("console-output-drain".into())
            .stack_size(64 * 1024)
            .spawn(move || io::copy(&mut output, &mut io::sink()))
            .map_err(|source| Error {
                operation: "start console output drain",
                source,
            })?;
        let mut console = 0;
        // SAFETY: live synchronous pipe ends, valid dimensions and writable
        // output. No cursor inheritance or default-terminal window is requested.
        let result = unsafe {
            CreatePseudoConsole(
                COORD { X: 80, Y: 25 },
                input_read.as_raw_handle(),
                output_write.as_raw_handle(),
                0,
                &mut console,
            )
        };
        if result < 0 {
            // Dropping the writer releases the reader even on creation failure.
            drop(output_write);
            let _ = drain.join();
            return Err(Error {
                operation: "CreatePseudoConsole",
                source: io::Error::other(format!("HRESULT 0x{:08x}", result as u32)),
            });
        }
        Ok(Self {
            console,
            _input: input_write,
            creator_channels: Some((input_read, output_write)),
            drain: Some(drain),
        })
    }

    pub fn handle(&self) -> &HPCON {
        &self.console
    }

    /// Close creator copies after the root has attached. The pseudoconsole
    /// retains its own channel references until ClosePseudoConsole.
    pub fn connected(&mut self) {
        self.creator_channels = None;
    }
}

impl Drop for PseudoConsole {
    fn drop(&mut self) {
        // The caller retains this owner through client retirement. The reader stays active
        // throughout closing so terminal output cannot fill a pipe and deadlock.
        // SAFETY: this object uniquely owns this successful creation's HPCON.
        unsafe { ClosePseudoConsole(self.console) };
        self.creator_channels = None;
        if let Some(drain) = self.drain.take() {
            // Rendering is intentionally discarded; it is never provider stdout
            // or a source of lifecycle/exit evidence. Closing releases the reader.
            let _ = drain.join();
        }
    }
}

fn pipe() -> Result<(OwnedHandle, OwnedHandle)> {
    let mut read: HANDLE = ptr::null_mut();
    let mut write: HANDLE = ptr::null_mut();
    // SAFETY: writable outputs, null attributes request noninheritable handles;
    // outputs immediately transfer to separate RAII owners on success.
    if unsafe { CreatePipe(&mut read, &mut write, ptr::null(), 0) } == 0 {
        return Err(last("create console channel"));
    }
    Ok((
        handle(read, "own console pipe reader")?,
        handle(write, "own console pipe writer")?,
    ))
}
