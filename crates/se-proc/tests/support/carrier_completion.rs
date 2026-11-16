//! Protects: failed native removal reaches the real output pipe as a failure,
//! rather than becoming an unknown outcome at a path-encoding boundary.
use super::*;
use crate::{native_ipc, uninstall::entry_effects};
use std::{ffi::OsString, mem::zeroed, ptr, sync::Arc, time::Instant};
use windows_sys::Win32::System::{IO::*, Pipes::*};

struct Receiver {
    server: Option<OwnedHandle>,
    event: OwnedHandle,
    operation: Box<OVERLAPPED>,
    pending: bool,
    _reservation: native_ipc::NativePipeReservation,
}
impl Receiver {
    fn new(name: &str) -> Check<Self> {
        let path = OsString::from(format!(r"\\.\pipe\{name}"));
        let reservation = native_ipc::NativePipeReservation::create(&path)?;
        let wide: Vec<_> = path.encode_wide().chain(Some(0)).collect();
        // The held first instance owns this random name and its owner-only DACL.
        // SAFETY: bounded terminated name; successful handle is immediately owned.
        let server = native::handle(
            unsafe {
                CreateNamedPipeW(
                    wide.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    PIPE_UNLIMITED_INSTANCES,
                    65536,
                    65536,
                    0,
                    ptr::null(),
                )
            },
            "create completion judge receiver",
        )?;
        // SAFETY: creates one unnamed noninherited manual-reset event.
        let event = native::handle(
            unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) },
            "create completion judge event",
        )?;
        // SAFETY: zero is the documented initial OVERLAPPED state; the box pins
        // it until completion, including cancellation in Receiver::drop.
        let mut operation: Box<OVERLAPPED> = Box::new(unsafe { zeroed() });
        operation.hEvent = event.as_raw_handle();
        let mut receiver = Self {
            server: Some(server),
            event,
            operation,
            pending: false,
            _reservation: reservation,
        };
        // SAFETY: retained pipe/event and stable boxed OVERLAPPED; Drop drains it.
        if unsafe { ConnectNamedPipe(receiver.raw()?, &mut *receiver.operation) } == 0 {
            let cause = io::Error::last_os_error();
            match cause.raw_os_error() {
                Some(code) if code == ERROR_IO_PENDING as i32 => receiver.pending = true,
                Some(code) if code == ERROR_PIPE_CONNECTED as i32 => (),
                _ => return Err(cause.into()),
            }
        }
        Ok(receiver)
    }
    fn raw(&self) -> Check<HANDLE> {
        Ok(self
            .server
            .as_ref()
            .ok_or("receiver handle absent")?
            .as_raw_handle())
    }
    fn read(mut self) -> Check<serde_json::Value> {
        if self.pending {
            // SAFETY: exact retained connection event and a bounded wait.
            if unsafe { WaitForSingleObject(self.event.as_raw_handle(), 5000) } != WAIT_OBJECT_0 {
                return Err("completion judge connection deadline".into());
            }
            let mut transferred = 0;
            // SAFETY: same live pipe and pinned OVERLAPPED; no blocking wait.
            if unsafe { GetOverlappedResult(self.raw()?, &*self.operation, &mut transferred, 0) }
                == 0
            {
                return Err(io::Error::last_os_error().into());
            }
            self.pending = false;
        }
        let bound = native_ipc::IpcIoBound {
            deadline: Instant::now() + Duration::from_secs(5),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        };
        let stream = native_ipc::NativePipeStream::worker_inherited(
            self.server.take().ok_or("receiver handle absent")?,
            bound,
        )?;
        let mut bytes = Vec::new();
        stream.take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 || !bytes.ends_with(b"\n") {
            return Err("completion judge reply absent, incomplete or oversized".into());
        }
        Ok(serde_json::from_slice(&bytes)?)
    }
}
impl Drop for Receiver {
    fn drop(&mut self) {
        if self.pending
            && let Some(server) = &self.server
        {
            let mut transferred = 0;
            // SAFETY: cancel and join only this fixture's exact operation before
            // releasing its buffer/event; no process or name-based cancellation.
            unsafe {
                CancelIoEx(server.as_raw_handle(), &*self.operation);
                GetOverlappedResult(
                    server.as_raw_handle(),
                    &*self.operation,
                    &mut transferred,
                    1,
                );
            }
        }
    }
}

#[test]
fn failed_removal_arrives_as_incomplete_on_the_actual_local_pipe() -> Check {
    let home = Home::new()?;
    let directory = home.0.join("directory");
    let original = home.0.join("original");
    std::fs::create_dir(&directory)?;
    let pin = crate::state_files::windows::effects::uninstall_directory(&directory)?
        .ok_or("original directory absent")?;
    let mut objects = inventory(&home.0, &directory, &pin, "completion")?;
    std::fs::rename(&directory, &original)?;
    std::fs::create_dir(&directory)?;
    std::fs::write(directory.join("foreign.txt"), b"preserve replacement")?;
    let Err(failure) = entry_effects::remove(&mut objects) else {
        return Err("replacement removal unexpectedly succeeded".into());
    };
    assert_eq!(failure.operation, "unlink carrier directory");
    let mut entropy = [0; 16];
    crate::fill_entropy(&mut entropy)?;
    let name = format!("stateengine-uninstall-{}", se_types::hex_lower(&entropy));
    let receiver = Receiver::new(&name)?;
    let token = "synthetic-reply-token";
    let report = serde_json::json!({
        "completion":{"pipe":name,"token":token}, "achieved":{"fixture":"failed removal"}
    });
    entry_effects::complete(&objects, &report, Some(&failure))?;
    let reply = receiver.read()?;
    assert_eq!(reply["schema"], "se.uninstall-completion/v2");
    assert_eq!(reply["token"], token);
    assert_eq!(reply["complete"], false);
    assert_eq!(reply["error"], failure.to_string());
    assert_eq!(reply["achieved"], report["achieved"]);
    assert!(original.is_dir());
    assert_eq!(
        std::fs::read(directory.join("foreign.txt"))?,
        b"preserve replacement"
    );
    Ok(())
}
