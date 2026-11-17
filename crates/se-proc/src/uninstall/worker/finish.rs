//! Output-only completion, after independently witnessing native effects.
use super::*;
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;

pub(super) fn send(
    completion: &serde_json::Value,
    report: &serde_json::Value,
    objects: &[Object],
    failure: Option<&UninstallNativeError>,
) -> Result<()> {
    let pipe = completion
        .get("pipe")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| refuse("deliver uninstall completion", "pipe name absent"))?;
    let token = completion
        .get("token")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| refuse("deliver uninstall completion", "reply token absent"))?;
    if !pipe.starts_with("stateengine-uninstall-")
        || pipe.len() != 54
        || !pipe[22..].bytes().all(|c| c.is_ascii_hexdigit())
        || token.len() != 64
        || !token.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return Err(refuse(
            "deliver uninstall completion",
            "invalid local output channel",
        ));
    }
    // This is a local pipe namespace, not a filesystem path. The validated
    // ASCII suffix and fixed prefix cannot contain an embedded NUL.
    let wide: Vec<u16> = format!(r"\\.\pipe\{pipe}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: bounded literal local named-pipe name and finite wait.
    if unsafe { WaitNamedPipeW(wide.as_ptr(), 5000) } == 0 {
        return Err(native::last("wait for uninstall completion reader"));
    }
    let file = native::handle(
        // SAFETY: validated local pipe name; identification prevents impersonation.
        unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        },
        "connect uninstall completion reader",
    )?;
    let find = |kind: &str| {
        objects
            .iter()
            .find(|object| object.entry.kind == kind)
            .map(|object| &object.entry.path)
    };
    let response = serde_json::json!({"schema":"se.uninstall-completion/v2", "token":token,
        "complete":failure.is_none(), "error":failure.map(ToString::to_string),
        "image":find("image"), "record":find("record"), "helper":null,
        "directory":find("staging"), "achieved":report.get("achieved")});
    let mut bytes = serde_json::to_vec(&response)
        .map_err(|cause| error("encode uninstall completion", io::Error::other(cause)))?;
    bytes.push(b'\n');
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(refuse(
            "deliver uninstall completion",
            "reply exceeds two MiB",
        ));
    }
    File::from(file)
        .write_all(&bytes)
        .map_err(|cause| error("deliver uninstall completion", cause))
}
