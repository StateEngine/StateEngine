//! Last-close carrier for Windows' mapped-image deletion restriction. The fixed
//! system executable receives two native objects and a private readiness pipe,
//! never a pathname or core plan. It cannot select anything to uninstall.
use super::*;

#[cfg(test)]
#[path = "../../tests/support/uninstall_carrier_environment.rs"]
mod environment_tests;
use std::os::windows::{
    ffi::{OsStrExt, OsStringExt},
    io::AsRawHandle,
};

pub(super) struct Carrier {
    process: OwnedHandle,
    ready: File,
    nonce: [u8; 32],
    deadline: u64,
    ready_seen: bool,
}
impl Carrier {
    pub fn start(
        image: &File,
        deadline: u64,
        root: &Path,
        directory: Option<&staging::DirectoryCustody>,
    ) -> Result<Self> {
        check_deadline(deadline)?;
        let directory = directory
            .map(|directory| staging::arm_directory_cleanup(directory, deadline))
            .transpose()?;
        let directory = directory
            .as_ref()
            .map(|file| native::duplicate_same(file.as_raw_handle(), true))
            .transpose()?;
        let process = native::current_process()?;
        let process = native::duplicate_same(process.as_raw_handle(), true)?;
        // This duplicate refers to the prelaunch delete-on-close file object.
        // Closing it after the helper's real exit lets the kernel delete it.
        let image = native::duplicate_same(image.as_raw_handle(), true)?;
        let (ready, write) = native::pipe()?;
        let write = native::duplicate_same(write.as_raw_handle(), true)?;
        let mut nonce = [0; 32];
        // SAFETY: fixed owned output and the system-preferred entropy provider.
        if unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                nonce.as_mut_ptr(),
                32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        } < 0
        {
            return Err(refuse("prepare helper cleanup", "native entropy failed"));
        }
        let mut acknowledgment = vec![b'R'];
        acknowledgment.extend_from_slice(&nonce);
        let acknowledgment = acknowledgment
            .iter()
            .map(u8::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let expires = deadline
            .checked_add(5000)
            .ok_or_else(|| refuse("prepare helper cleanup", "deadline overflow"))?;
        let script = format!(
            r#"
$ErrorActionPreference='Stop'
try {{
$process=[Microsoft.Win32.SafeHandles.SafeWaitHandle]::new([System.IntPtr]::new([System.Int64]{process}),$true)
$image=[Microsoft.Win32.SafeHandles.SafeFileHandle]::new([System.IntPtr]::new([System.Int64]{image}),$true)
$directory=$null
if ([System.Int64]{directory} -ne 0) {{ $directory=[Microsoft.Win32.SafeHandles.SafeFileHandle]::new([System.IntPtr]::new([System.Int64]{directory}),$true) }}
$ready=[Microsoft.Win32.SafeHandles.SafeFileHandle]::new([System.IntPtr]::new([System.Int64]{ready}),$true)
$event=[System.Threading.ManualResetEvent]::new($false)
$event.SafeWaitHandle=$process
[System.Threading.WaitHandle]$waiter=$event
$stream=[System.IO.FileStream]::new($ready,[System.IO.FileAccess]::Write)
$now=([System.Int64][System.Environment]::TickCount -band 4294967295)
$wait=([System.Int64]{expires}-$now+4294967296) -band 4294967295
if ($wait -gt 305000 -or $wait -eq 0) {{ exit 72 }}
$bytes=[System.Byte[]]@({acknowledgment})
$stream.Write($bytes,0,33); $stream.Flush(); $stream.Dispose()
if (-not $waiter.WaitOne([System.Int32]$wait)) {{ exit 75 }}
$image.Dispose()
if ($null -ne $directory) {{ $directory.Dispose() }}
$waiter.Dispose()
exit 0
}} catch {{ [System.Console]::Error.WriteLine($_.Exception.Message); exit 78 }}
"#,
            process = process.as_raw_handle() as usize,
            image = image.as_raw_handle() as usize,
            ready = write.as_raw_handle() as usize,
            expires = expires as u32,
            directory = directory
                .as_ref()
                .map_or(0, |file| file.as_raw_handle() as usize),
        );
        let mut line: Vec<u16> = format!(
            "powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand {}",
            encode(&script)?
        )
        .encode_utf16()
        .chain(Some(0))
        .collect();
        let mut inherited = vec![process.as_raw_handle(), write.as_raw_handle()];
        if let Some(directory) = &directory {
            inherited.push(directory.as_raw_handle());
        }
        // Windows PowerShell uses .NET Framework configuration readers which
        // do not share the native file adapter's verbatim-path behavior. This
        // trusted system executable uses its ordinary absolute Win32 spelling.
        let application: Vec<_> = system_powershell()?
            .as_os_str()
            .encode_wide()
            .chain(Some(0))
            .collect();
        let process = spawn::command(
            &application,
            &mut line,
            &image,
            &inherited,
            CREATE_NO_WINDOW,
            Some(&environment(root)?),
        )?;
        Ok(Self {
            process,
            ready,
            nonce,
            deadline,
            ready_seen: false,
        })
    }
    pub fn ensure_ready(&mut self) -> Result<()> {
        let until = self.deadline.min(clock().saturating_add(15000));
        while !self.ready_seen {
            check_deadline(until)?;
            if native::exited(&self.process)? {
                return Err(refuse(
                    "prepare helper cleanup",
                    "system cleanup carrier exited before readiness",
                ));
            }
            if let Some(frame) = native::poll_frame(&mut self.ready)? {
                if frame[0] != b'R' || frame[1..] != self.nonce {
                    return Err(refuse(
                        "prepare helper cleanup",
                        "private carrier acknowledgment mismatch",
                    ));
                }
                self.ready_seen = true;
            } else {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        Ok(())
    }
}
fn environment(root: &Path) -> Result<Vec<u16>> {
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
fn system_powershell() -> Result<PathBuf> {
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
fn encode(script: &str) -> Result<String> {
    let bytes: Vec<_> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
    let mut count = 0;
    // SAFETY: owned bounded UTF-16LE source and documented output sizing query.
    if unsafe {
        CryptBinaryToStringW(
            bytes.as_ptr(),
            bytes.len() as u32,
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            std::ptr::null_mut(),
            &mut count,
        )
    } == 0
    {
        return Err(native::last("encode fixed cleanup carrier"));
    }
    if count == 0 || count > 16000 {
        return Err(refuse(
            "encode fixed cleanup carrier",
            "command capacity exceeded",
        ));
    }
    let mut text = vec![0u16; count as usize];
    // SAFETY: source and exactly sized initialized output survive the encoding call.
    if unsafe {
        CryptBinaryToStringW(
            bytes.as_ptr(),
            bytes.len() as u32,
            CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF,
            text.as_mut_ptr(),
            &mut count,
        )
    } == 0
    {
        return Err(native::last("encode fixed cleanup carrier"));
    }
    let length = text
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(text.len());
    String::from_utf16(&text[..length])
        .map_err(|_| refuse("encode fixed cleanup carrier", "invalid encoded output"))
}
