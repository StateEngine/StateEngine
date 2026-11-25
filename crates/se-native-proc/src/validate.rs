use crate::support::*;
use crate::*;
use sha2::{Digest, Sha256};
use std::{collections::HashSet, ffi::OsStr, path::PathBuf};

#[cfg(all(test, windows))]
mod tests;

/// Immutable launch contract bound to a prepared native `Scope`.
/// Enforces one-shot `Driver::begin` and prevents direct `se-native-proc`
/// callers from changing policy/paths/argv or bypassing NUL validation.
pub(crate) struct LaunchBinding {
    lifecycle: LifecycleId,
    generation: GenerationId,
    mode: LaunchMode,
    window: Option<WindowSpec>,
    policy: LaunchPolicy,
    executable: PathBuf,
    cwd: PathBuf,
    argv_sha256: [u8; 32],
    launched: bool,
}

impl LaunchBinding {
    pub(crate) fn prepare(reservation: &LaunchReservation, spec: &LaunchSpec) -> ProcResult<Self> {
        if reservation.format_version != 1 {
            return Err(input("reservation version", "expected 1"));
        }
        if reservation.lifecycle != spec.lifecycle || reservation.generation != spec.generation {
            return Err(input(
                "launch reservation",
                "lifecycle and generation must match",
            ));
        }
        spec_preconditions(spec)?;
        working_directory(spec)?;
        let argv_sha256 = argv_digest(spec)?;
        Ok(Self {
            lifecycle: spec.lifecycle.clone(),
            generation: spec.generation,
            mode: spec.mode,
            window: spec.window.clone(),
            policy: spec.policy.clone(),
            executable: spec.executable.clone(),
            cwd: spec.cwd.clone(),
            argv_sha256,
            launched: false,
        })
    }
}

pub(crate) fn begin_bound(
    binding: &mut Option<LaunchBinding>,
    spec: &LaunchSpec,
) -> ProcResult<()> {
    let Some(bound) = binding.as_mut() else {
        return Err(error(
            ProcErrorCode::IllegalTransition,
            ProcErrorDetail::Input {
                field: "launch".into(),
                reason: "recovered scope cannot begin a new launch".into(),
            },
        ));
    };
    if bound.launched {
        return Err(error(
            ProcErrorCode::IllegalTransition,
            ProcErrorDetail::Input {
                field: "launch".into(),
                reason: "prepared scope has already begun launch".into(),
            },
        ));
    }
    spec_preconditions(spec)?;
    working_directory(spec)?;
    let digest = argv_digest(spec)?;
    if spec.lifecycle != bound.lifecycle
        || spec.generation != bound.generation
        || spec.mode != bound.mode
        || spec.window != bound.window
        || spec.policy != bound.policy
        || spec.executable != bound.executable
        || spec.cwd != bound.cwd
        || digest != bound.argv_sha256
    {
        return Err(input(
            "launch spec",
            "launch spec does not match prepared scope",
        ));
    }
    bound.launched = true;
    Ok(())
}

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
/// Checks run in this order, so the same input reports the same first refusal.
pub fn spec(
    reservation: &LaunchReservation,
    spec: &LaunchSpec,
    config: &HostConfig,
    owner: &ProcessIdentity,
) -> ProcResult<[u8; 32]> {
    preconditions(reservation, spec, config, owner)?;
    working_directory(spec)?;
    argv_digest(spec)
}
/// Reservation binding, deadline, image custody, capacity, hardening and mode.
fn preconditions(
    reservation: &LaunchReservation,
    spec: &LaunchSpec,
    config: &HostConfig,
    owner: &ProcessIdentity,
) -> ProcResult<()> {
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
    spec_preconditions(spec)
}
fn spec_preconditions(spec: &LaunchSpec) -> ProcResult<()> {
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
    if let Some(image) = &spec.executable_custody {
        let selected = crate::canonicalize_path(&spec.executable)
            .map_err(|e| native(ProcErrorCode::LaunchFailed, "resolve qualified image", e))?;
        if selected != image.original_path() || spec.window.is_some() {
            return Err(input(
                "qualified image",
                "original native image and a headless launch required",
            ));
        }
        image
            .validate()
            .map_err(|e| input("qualified image", &e.to_string()))?;
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
    Ok(())
}
/// The resolved cwd must be a directory inside the selected write policy.
fn working_directory(spec: &LaunchSpec) -> ProcResult<()> {
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
    Ok(())
}
/// Bounded NUL-free native bytes, unique environment keys, and the argv digest.
fn argv_digest(spec: &LaunchSpec) -> ProcResult<[u8; 32]> {
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
