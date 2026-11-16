//! Fixed system interpreter and minimal environment for the readable carrier.
use super::*;
use std::os::windows::ffi::{OsStrExt, OsStringExt};

#[cfg(test)]
#[path = "../../tests/support/uninstall_carrier_environment.rs"]
mod environment_tests;

pub(super) fn environment(root: &Path) -> Result<Vec<u16>> {
    let mut windows = vec![0u16; 32768];
    // SAFETY: initialized UTF-16 output and explicit capacity for the native Windows directory.
    let count = unsafe {
        windows_sys::Win32::System::SystemInformation::GetWindowsDirectoryW(
            windows.as_mut_ptr(),
            windows.len() as u32,
        )
    } as usize;
    if count == 0 || count >= windows.len() {
        return Err(native::last("resolve cleanup Windows directory"));
    }
    let windows = std::ffi::OsString::from_wide(&windows[..count]);
    let mut block = Vec::new();
    // Fixed allowlist. No caller environment, module paths, profiler hooks,
    // framework configuration or command search path reaches the carrier.
    for (name, value) in [
        ("SystemRoot", windows.as_os_str()),
        ("TEMP", root.as_os_str()),
        ("TMP", root.as_os_str()),
        ("windir", windows.as_os_str()),
    ] {
        block.extend(name.encode_utf16());
        block.push(b'=' as u16);
        let units: Vec<_> = value.encode_wide().collect();
        if units.contains(&0) {
            return Err(refuse("prepare cleanup environment", "NUL in native path"));
        }
        block.extend(units);
        block.push(0);
    }
    block.push(0);
    Ok(block)
}
pub(super) fn system_powershell() -> Result<PathBuf> {
    let mut path = vec![0u16; 32768];
    // SAFETY: initialized UTF-16 output with explicit native capacity.
    let count = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
            path.as_mut_ptr(),
            path.len() as u32,
        )
    } as usize;
    if count == 0 || count >= path.len() {
        return Err(native::last("resolve system cleanup executable"));
    }
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&path[..count]))
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("powershell.exe"))
}

// Load the pinned script without target objects or a compiler process.
pub(super) fn admit(
    script: &Path,
    environment: &[u16],
    diagnostic: &File,
    until: u64,
) -> Result<()> {
    let application = native::wide(&cleanup::system_powershell()?)?;
    let mut line: Vec<u16> = format!(
        "powershell.exe -NoLogo -NoProfile -NonInteractive -File \"{}\"",
        script.display()
    )
    .encode_utf16()
    .chain(Some(0))
    .collect();
    let sink = File::open(r"\\.\NUL").map_err(|e| error("open policy gate input", e))?;
    let input = native::duplicate_same(sink.as_raw_handle(), true)?;
    let process = spawn::command(
        &application,
        &mut line,
        &input,
        &[],
        CREATE_NO_WINDOW,
        Some(environment),
        Some(diagnostic),
    )?;
    let outcome = (|| {
        loop {
            if native::exited(&process)? {
                let mut code = 0;
                // SAFETY: retained exact process and writable exit status output.
                if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut code) } == 0 {
                    return Err(native::last("read uninstall policy status"));
                }
                return if code == 78 {
                    Ok(())
                } else {
                    Err(refuse(
                        "prepare uninstall carrier",
                        "system carrier exited; installation remains unchanged",
                    ))
                };
            }
            if clock() >= until {
                return Err(refuse(
                    "prepare uninstall carrier",
                    "system policy gate deadline; installation remains unchanged",
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    })();
    if outcome.is_err() {
        super::carrier::cancel_preparation(&process)?;
    }
    outcome
}
