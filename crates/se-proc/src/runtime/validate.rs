use crate::support::*;
use crate::*;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, ffi::OsStr};

fn units(value: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        value.encode_wide().flat_map(u16::to_le_bytes).collect()
    }
}
pub(super) fn spec(
    reservation: &LaunchReservation,
    spec: &LaunchSpec,
    config: &HostConfig,
    owner: &ProcessIdentity,
) -> ProcResult<[u8; 32]> {
    if reservation.format_version != 1 {
        return Err(input("reservation version", "expected 1"));
    }
    if reservation.lifecycle != spec.lifecycle
        || reservation.generation != spec.generation
        || reservation.host != config.instance
        || &reservation.owner != owner
    {
        return Err(input(
            "launch reservation",
            "lifecycle, generation, host and exact owner must match",
        ));
    }
    if spec.deadline <= std::time::Instant::now() {
        return Err(error(
            ProcErrorCode::LaunchTimedOut,
            ProcErrorDetail::Input {
                field: "deadline".into(),
                reason: "launch deadline elapsed".into(),
            },
        ));
    }
    if !spec.executable.is_absolute() || !spec.cwd.is_absolute() {
        return Err(input(
            "launch paths",
            "absolute executable and cwd required",
        ));
    }
    if spec.arguments.len() > 1024 || spec.environment.entries.len() > 1024 {
        return Err(capacity("argument/environment count", 1024));
    }
    if !matches!(spec.policy.hardening, OptionalHardening::Off) {
        return Err(error(
            ProcErrorCode::HardeningUnavailable,
            ProcErrorDetail::Input {
                field: "hardening".into(),
                reason: "no optional native hardening profile is installed".into(),
            },
        ));
    }
    if (spec.mode == LaunchMode::Window) != spec.window.is_some() {
        return Err(input(
            "window",
            "window launch requires its platform window specification",
        ));
    }
    let cwd = std::fs::canonicalize(&spec.cwd)
        .map_err(|e| native(ProcErrorCode::LaunchFailed, "resolve cwd", e))?;
    if !cwd.is_dir() {
        return Err(input("cwd", "must name a directory"));
    }
    if let WritePolicy::Workspace { roots, .. } = &spec.policy.writes {
        let mut allowed = false;
        for root in roots {
            if !root.is_absolute() {
                return Err(input("workspace", "absolute roots required"));
            }
            let root = std::fs::canonicalize(root)
                .map_err(|e| native(ProcErrorCode::CwdOutsideWorkspace, "resolve workspace", e))?;
            allowed |= cwd.starts_with(root);
        }
        if !allowed {
            return Err(error(
                ProcErrorCode::CwdOutsideWorkspace,
                ProcErrorDetail::Workspace {
                    cwd: spec.cwd.clone(),
                    workspace: roots.first().cloned().unwrap_or_default(),
                },
            ));
        }
    }
    if let WritePolicy::NamedUnrestricted { profile } = &spec.policy.writes
        && (profile.is_empty() || profile.len() > 128)
    {
        return Err(input("profile", "a bounded saved profile name is required"));
    }
    let mut size = 0usize;
    let mut check = |value: &OsStr, field: &str| -> ProcResult<Vec<u8>> {
        let bytes = units(value);
        #[cfg(unix)]
        let nul = bytes.contains(&0);
        #[cfg(windows)]
        let nul = bytes.chunks_exact(2).any(|b| b == [0, 0]);
        if nul {
            return Err(input(field, "NUL is not permitted"));
        }
        size = size
            .checked_add(bytes.len())
            .ok_or_else(|| capacity("native launch bytes", 65536))?;
        if size > 65536 {
            return Err(capacity("native launch bytes", 65536));
        }
        Ok(bytes)
    };
    let mut digest = Sha256::new();
    for arg in std::iter::once(spec.executable.as_os_str())
        .chain(spec.arguments.iter().map(|a| a.as_os_str()))
    {
        let bytes = check(arg, "argument")?;
        digest.update((bytes.len() as u64).to_le_bytes());
        digest.update(bytes);
    }
    check(spec.cwd.as_os_str(), "cwd")?;
    let mut keys = HashSet::new();
    for (key, value) in &spec.environment.entries {
        if key.is_empty() || key.to_string_lossy().contains('=') {
            return Err(input(
                "environment key",
                "nonempty keys without '=' required",
            ));
        }
        let _bytes = check(key, "environment key")?;
        #[cfg(not(windows))]
        let bytes = _bytes;
        #[cfg(windows)]
        let bytes = key.to_string_lossy().to_uppercase().into_bytes();
        if !keys.insert(bytes) {
            return Err(input("environment key", "duplicate key"));
        }
        check(value, "environment value")?;
    }
    Ok(digest.finalize().into())
}
