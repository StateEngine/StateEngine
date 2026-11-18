//! A private console for Ctrl+C and console-using descendants. Protocol stdio
//! remains on its explicit pipes; terminal rendering is drained to a sink.
use super::identity::{Handle, last};
use crate::{ProcErrorCode, ProcResult, support::native};
use std::{fs::File, io, os::windows::io::FromRawHandle, ptr, thread};
use windows_sys::Win32::{
    Foundation::HANDLE,
    System::{Console::*, Pipes::CreatePipe},
};

pub(super) struct PseudoConsole {
    console: HPCON,
    // Keep input open without injecting terminal bytes into the protocol.
    _input: Handle,
    creator_channels: Option<(Handle, Handle)>,
    drain: Option<thread::JoinHandle<io::Result<u64>>>,
}

impl PseudoConsole {
    pub fn new() -> ProcResult<Self> {
        let (input_read, input_write) = pipe()?;
        let (output_read, output_write) = pipe()?;
        // Transfer the reader to File before spawning: failed thread creation
        // also closes it. No channel is inheritable by arbitrary child processes.
        let mut output_read = output_read;
        let raw = std::mem::replace(&mut output_read.0, ptr::null_mut());
        // SAFETY: ownership of this valid synchronous pipe handle leaves Handle
        // and transfers exactly once to File, which is moved into the worker.
        let mut output = unsafe { File::from_raw_handle(raw) };
        let drain = thread::Builder::new()
            .name("console-output-drain".into())
            .stack_size(64 * 1024)
            .spawn(move || io::copy(&mut output, &mut io::sink()))
            .map_err(|e| native(ProcErrorCode::LaunchFailed, "start console output drain", e))?;
        let mut console = 0;
        // SAFETY: live synchronous pipe ends, valid dimensions and writable
        // output. No cursor inheritance or default-terminal window is requested.
        let result = unsafe {
            CreatePseudoConsole(
                COORD { X: 80, Y: 25 },
                input_read.0,
                output_write.0,
                0,
                &mut console,
            )
        };
        if result < 0 {
            // Dropping the writer releases the reader even on creation failure.
            drop(output_write);
            let _ = drain.join();
            return Err(native(
                ProcErrorCode::LaunchFailed,
                "CreatePseudoConsole",
                io::Error::other(format!("HRESULT 0x{:08x}", result as u32)),
            ));
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
        // On failed creation there is no client; on normal release the job has
        // already been witnessed empty. The independent reader stays active
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

fn pipe() -> ProcResult<(Handle, Handle)> {
    let mut read: HANDLE = ptr::null_mut();
    let mut write: HANDLE = ptr::null_mut();
    // SAFETY: writable outputs, null attributes request noninheritable handles;
    // outputs immediately transfer to separate RAII owners on success.
    if unsafe { CreatePipe(&mut read, &mut write, ptr::null(), 0) } == 0 {
        return Err(last(ProcErrorCode::LaunchFailed, "create console channel"));
    }
    Ok((Handle(read), Handle(write)))
}
