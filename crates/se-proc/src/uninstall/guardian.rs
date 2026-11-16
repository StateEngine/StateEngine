//! The fixed interpreter retains exact child and claim handles. It receives
//! no authority over original installation files; Rust performs those effects.
use super::*;
use std::os::windows::ffi::OsStrExt;

pub(super) struct Guardian {
    pub process: OwnedHandle,
    pub ready: File,
}
pub(super) fn start(
    files: &NativeStateFiles,
    script: &Path,
    environment: &[u16],
    diagnostic: &File,
    mut frame: serde_json::Value,
    handles: [HANDLE; 5],
) -> Result<Guardian> {
    let (ready, write) = native::pipe()?;
    let mut control = Vec::new();
    for raw in handles[..3]
        .iter()
        .copied()
        .chain(Some(write.as_raw_handle()))
        .chain(handles[3..].iter().copied())
    {
        control.push(native::duplicate_same(raw, true)?);
    }
    for (name, handle) in [
        "process",
        "claim",
        "report",
        "ready",
        "copy_handle",
        "journal_handle",
    ]
    .into_iter()
    .zip(&control)
    {
        frame[name] = serde_json::json!(handle.as_raw_handle() as usize as u64);
    }
    let input = envelope(files, &frame)?;
    let application: Vec<u16> = cleanup::system_powershell()?
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut line: Vec<u16> = format!(
        "powershell.exe -NoLogo -NoProfile -NonInteractive -File \"{}\"",
        script.display()
    )
    .encode_utf16()
    .chain(Some(0))
    .collect();
    let inherited: Vec<_> = control.iter().map(AsRawHandle::as_raw_handle).collect();
    let process = spawn::command(
        &application,
        &mut line,
        &input,
        &inherited,
        CREATE_NO_WINDOW,
        Some(environment),
        Some(diagnostic),
    )?;
    Ok(Guardian { process, ready })
}

/// Anonymous disk input cannot retain a name or block on an interpreter's pipe.
pub(super) fn envelope(files: &NativeStateFiles, value: &serde_json::Value) -> Result<OwnedHandle> {
    let mut file = files
        .retire_empty_staging(files.create_staging(files.root()).map_err(custody)?)
        .map_err(custody)?;
    let bytes = serde_json::to_vec(value)
        .map_err(|e| error("encode private cleanup envelope", io::Error::other(e)))?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(refuse(
            "prepare private cleanup envelope",
            "two MiB bound exceeded",
        ));
    }
    file.write_all(&bytes)
        .and_then(|()| file.rewind())
        .map_err(|e| error("write private cleanup envelope", e))?;
    native::duplicate(file.as_raw_handle(), FILE_GENERIC_READ, true)
}

pub(super) fn await_ready(
    process: &OwnedHandle,
    ready: &mut File,
    nonce: &[u8; 32],
    until: u64,
) -> Result<()> {
    loop {
        if native::exited(process)? {
            return Err(refuse(
                "prepare uninstall carrier",
                "prepared child exited; installation remains unchanged",
            ));
        }
        if let Some(frame) = native::poll_frame(ready)? {
            if frame[0] != b'R' || frame[1..] != *nonce {
                return Err(refuse(
                    "prepare uninstall carrier",
                    "readiness authentication failed",
                ));
            }
            return Ok(());
        }
        if clock() >= until {
            return Err(refuse(
                "prepare uninstall carrier",
                "readiness deadline; installation remains unchanged",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
