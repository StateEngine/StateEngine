use super::*;

pub(super) fn endpoint_matches(
    endpoint: &File,
    expected: &ProcessIdentity,
    deadline: Instant,
) -> ProcResult<()> {
    use crate::native_ipc::*;
    #[cfg(unix)]
    use std::os::fd::AsFd;
    #[cfg(windows)]
    use std::os::windows::io::AsHandle;
    #[cfg(unix)]
    let channel = endpoint.as_fd();
    #[cfg(windows)]
    let channel = endpoint.as_handle();
    let bound = IpcIoBound {
        deadline,
        cancelled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };
    let peer = observe_ipc_peer_bounded(channel, IpcPeerSide::Server, &bound)
        .map_err(|e| input("runtime authenticated endpoint", &e.to_string()))?;
    let same_start = match (&expected.start, peer.started()) {
        (
            StartIdentity::Linux { start_ticks: a },
            se_types::StartIdentity::Linux { start_ticks: b },
        ) => a == b,
        (
            StartIdentity::Windows {
                creation_filetime: a,
            },
            se_types::StartIdentity::Windows {
                creation_filetime: b,
            },
        ) => *a == b.get(),
        _ => false,
    };
    let image = match peer.image().encoded() {
        #[cfg(unix)]
        se_types::PathEncoding::UnixBytes(bytes) => {
            use std::os::unix::ffi::OsStringExt;
            PathBuf::from(std::ffi::OsString::from_vec(bytes.clone()))
        }
        #[cfg(windows)]
        se_types::PathEncoding::WindowsUtf16(units) => {
            use std::os::windows::ffi::OsStringExt;
            PathBuf::from(std::ffi::OsString::from_wide(units))
        }
        _ => return Err(input("runtime peer", "foreign native path encoding")),
    };
    if peer.pid() != expected.pid.0 || !same_start || image != expected.image {
        return Err(input(
            "runtime peer",
            "authenticated endpoint differs from pinned runtime child",
        ));
    }
    Ok(())
}
pub(super) fn validate_spec(spec: &RuntimeLaunchSpec) -> ProcResult<()> {
    use std::collections::HashSet;
    if spec.environment.entries.len() > 1024 {
        return Err(capacity("runtime environment entries", 1024));
    }
    let mut total = 0usize;
    let mut check = |value: &std::ffi::OsStr| -> ProcResult<()> {
        let path = PathBuf::from(value);
        let encoded = crate::checkpoint::native_path::encoded(&path)
            .map_err(|e| input("runtime native value", e))?;
        let bytes = match encoded {
            se_types::PathEncoding::UnixBytes(bytes) => bytes.len(),
            se_types::PathEncoding::WindowsUtf16(units) => units.len() * 2,
        };
        total = total
            .checked_add(bytes)
            .ok_or_else(|| capacity("runtime native arguments/environment bytes", 65536))?;
        if total > 65536 {
            return Err(capacity(
                "runtime native arguments/environment bytes",
                65536,
            ));
        }
        Ok(())
    };
    check(spec.executable.as_os_str())?;
    for arg in &spec.arguments {
        check(arg)?;
    }
    let mut keys = HashSet::new();
    for (key, value) in &spec.environment.entries {
        if key.is_empty() || key.to_string_lossy().contains('=') {
            return Err(input(
                "runtime environment",
                "nonempty names without '=' required",
            ));
        }
        check(key)?;
        check(value)?;
        #[cfg(windows)]
        let name = key.to_string_lossy().to_uppercase().into_bytes();
        #[cfg(unix)]
        let name = {
            use std::os::unix::ffi::OsStrExt;
            key.as_bytes().to_vec()
        };
        if !keys.insert(name) {
            return Err(input(
                "runtime environment",
                "duplicate native environment key",
            ));
        }
    }
    Ok(())
}
