//! Linux background lifetime admission. Failure preserves the existing session host.
mod bus;
mod peer;
mod symbols;
use crate::support::input;
use crate::{ProcResult, ProcessId, RuntimeLaunchSpec, RuntimeLifetime, RuntimeUserScope};
use bus::{Bus, name};
use peer::verify as verify_peer;
use std::{
    ffi::CStr,
    fs,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::Path,
};
use std::{
    fs::File,
    path::PathBuf,
    time::{Duration, Instant},
};

const MANAGER: &CStr = c"/org/freedesktop/systemd1";
const INTERFACE: &CStr = c"org.freedesktop.systemd1.Manager";

pub(crate) fn admit(pin: &File, pid: ProcessId, spec: &RuntimeLaunchSpec) -> RuntimeLifetime {
    match attempt(pin, pid, spec) {
        Ok(scope) => RuntimeLifetime {
            user_scope: Some(scope),
            session_reason: None,
        },
        Err(reason) => RuntimeLifetime {
            user_scope: None,
            session_reason: Some(reason),
        },
    }
}
fn attempt(
    pin: &File,
    pid: ProcessId,
    spec: &RuntimeLaunchSpec,
) -> Result<RuntimeUserScope, String> {
    lingering()?;
    // SAFETY: immutable native owner query, independent of process environment.
    let uid = unsafe { libc::geteuid() };
    let api = symbols::Api::load().ok_or("The native user-manager library is unavailable")?;
    // Manager discovery never accepts a caller-supplied bus address.
    let address = name(&format!("unix:path=/run/user/{uid}/systemd/private"))?;
    let deadline = admission_deadline(spec.deadline);
    let bus = Bus::connect(&api, &address, deadline, false)?;
    verify_peer(&bus, uid, deadline)?;
    let mut unit_nonce = [0; 16];
    crate::fill_entropy(&mut unit_nonce).map_err(|e| e.to_string())?;
    let unit = format!("se-runtime-{}.scope", se_types::hex_lower(&unit_nonce));
    let request = bus.request(MANAGER, INTERFACE, c"StartTransientUnit")?;
    request.string(b's', &name(&unit)?)?;
    request.string(b's', c"fail")?;
    request.open(b'a', c"(sv)")?;
    request.open(b'r', c"sv")?;
    request.string(b's', c"PIDFDs")?;
    request.open(b'v', c"ah")?;
    request.open(b'a', c"h")?;
    request.descriptor(&pin.as_raw_fd())?;
    request.close()?;
    request.close()?;
    request.close()?;
    request.open(b'r', c"sv")?;
    request.string(b's', c"CollectMode")?;
    request.open(b'v', c"s")?;
    request.string(b's', c"inactive-or-failed")?;
    request.close()?;
    request.close()?;
    request.close()?;
    request.open(b'a', c"(sa(sv))")?;
    request.close()?;
    let reply = bus
        .call(&request)
        .map_err(|e| format!("The user manager did not admit the pinned bootstrap: {e}"))?;
    let _job = reply.read_string(b'o')?;
    let request = bus.request(MANAGER, INTERFACE, c"GetUnit")?;
    request.string(b's', &name(&unit)?)?;
    let path = name(&bus.call(&request)?.read_string(b'o')?)?;
    loop {
        bus.remaining()?;
        let group = bus
            .property(
                &path,
                c"org.freedesktop.systemd1.Unit",
                c"ControlGroup",
                c"s",
            )?
            .read_string(b's')?;
        let active = bus
            .property(
                &path,
                c"org.freedesktop.systemd1.Unit",
                c"ActiveState",
                c"s",
            )?
            .read_string(b's')?;
        if active == "active" && valid_group(&group, uid, &unit) && in_group(pid, &group)? {
            let invocation = bus
                .property(
                    &path,
                    c"org.freedesktop.systemd1.Unit",
                    c"InvocationID",
                    c"ay",
                )?
                .bytes()?;
            if invocation.iter().all(|b| *b == 0) {
                return Err("User scope invocation identity is absent".into());
            }
            return Ok(RuntimeUserScope {
                unit,
                invocation: se_types::hex_lower(&invocation),
                cgroup: group,
            });
        }
        if active == "failed" {
            return Err("The user scope failed before bootstrap admission".into());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn lingering() -> Result<(), String> {
    let mut storage = vec![0u8; 65536];
    // SAFETY: native passwd output is initialized by the reentrant lookup below.
    let mut user: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found = std::ptr::null_mut();
    // SAFETY: native UID lookup uses exact retained output, buffer and result storage.
    let rc = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            &mut user,
            storage.as_mut_ptr().cast(),
            storage.len(),
            &mut found,
        )
    };
    if rc != 0 || found.is_null() || user.pw_name.is_null() {
        return Err("The native account's linger setting is unreadable".into());
    }
    // SAFETY: successful getpwuid_r returns a terminated name in the retained buffer.
    let account = unsafe { CStr::from_ptr(user.pw_name) }
        .to_str()
        .map_err(|e| e.to_string())?;
    if account.is_empty() || account.contains('/') || matches!(account, "." | "..") {
        return Err("The native account name is invalid".into());
    }
    for (path, directory) in [
        (PathBuf::from("/var/lib/systemd/linger"), true),
        (Path::new("/var/lib/systemd/linger").join(account), false),
    ] {
        let metadata = fs::symlink_metadata(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "Lingering is not enabled for this account".into()
            } else {
                format!("The account's linger setting is unreadable: {e}")
            }
        })?;
        if metadata.file_type().is_symlink()
            || (directory && !metadata.is_dir())
            || (!directory && !metadata.is_file())
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err("The account's linger setting is not administrator-protected".into());
        }
    }
    Ok(())
}
fn valid_group(group: &str, uid: u32, unit: &str) -> bool {
    let prefix = format!("/user.slice/user-{uid}.slice/user@{uid}.service/");
    let valid_unit = unit
        .strip_prefix("se-runtime-")
        .and_then(|name| name.strip_suffix(".scope"))
        .is_some_and(|nonce| {
            nonce.len() == 32
                && nonce
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
    valid_unit
        && group.starts_with(&prefix)
        && group.ends_with(&format!("/{unit}"))
        && !group.split('/').any(|part| matches!(part, "." | ".."))
}
pub(crate) fn verify(
    scope: &RuntimeUserScope,
    pid: ProcessId,
    deadline: Instant,
) -> Result<(), String> {
    lingering()?;
    // SAFETY: immutable native owner query.
    let uid = unsafe { libc::geteuid() };
    if !valid_group(&scope.cgroup, uid, &scope.unit) || !in_group(pid, &scope.cgroup)? {
        return Err("The exact runtime is outside its admitted user scope".into());
    }
    let api = symbols::Api::load().ok_or("The native user-manager library became unavailable")?;
    let address = name(&format!("unix:path=/run/user/{uid}/systemd/private"))?;
    let deadline = admission_deadline(deadline);
    let bus = Bus::connect(&api, &address, deadline, false)?;
    verify_peer(&bus, uid, deadline)?;
    let request = bus.request(MANAGER, INTERFACE, c"GetUnit")?;
    request.string(b's', &name(&scope.unit)?)?;
    let path = name(&bus.call(&request)?.read_string(b'o')?)?;
    let invocation = bus
        .property(
            &path,
            c"org.freedesktop.systemd1.Unit",
            c"InvocationID",
            c"ay",
        )?
        .bytes()?;
    let group = bus
        .property(
            &path,
            c"org.freedesktop.systemd1.Unit",
            c"ControlGroup",
            c"s",
        )?
        .read_string(b's')?;
    if se_types::hex_lower(&invocation) != scope.invocation || group != scope.cgroup {
        return Err("The admitted user scope identity changed before runtime authorization".into());
    }
    Ok(())
}
fn admission_deadline(deadline: Instant) -> Instant {
    let now = Instant::now();
    // Preserve most of the caller's remaining startup bound for its original
    // bootstrap. A slow optional manager is a session-lifetime fallback.
    now + (deadline.saturating_duration_since(now) / 4).min(Duration::from_secs(1))
}
/// Re-observe the admitted scope before a status reader reports its lifetime.
pub fn verify_runtime_user_scope(
    scope: &RuntimeUserScope,
    pid: ProcessId,
    deadline: Instant,
) -> ProcResult<()> {
    verify(scope, pid, deadline).map_err(|reason| input("runtime user scope", &reason))
}
pub(super) fn in_group(pid: ProcessId, expected: &str) -> Result<bool, String> {
    let text = fs::read_to_string(format!("/proc/{}/cgroup", pid.0)).map_err(|e| e.to_string())?;
    if text.len() > 65536 {
        return Err("The native cgroup fact exceeds its bound".into());
    }
    Ok(text
        .lines()
        .any(|line| line.strip_prefix("0::") == Some(expected)))
}
pub(crate) fn pin_launcher(pid: i32) -> ProcResult<File> {
    // SAFETY: this is the retained, unreaped direct child; PIDFDs prevent delayed manager requests from attaching a reused PID.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        return Err(input(
            "user scope bootstrap",
            &format!(
                "native launcher pin is unavailable: {}",
                std::io::Error::last_os_error()
            ),
        ));
    }
    // SAFETY: successful pidfd_open transferred this unique descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}
/// Observe only the recorded unit's kernel cgroup after exact host shutdown.
/// This never signals a unit or obtains authority over any process in it.
pub fn runtime_user_scope_empty(scope: &RuntimeUserScope) -> ProcResult<bool> {
    // SAFETY: immutable native owner query.
    let uid = unsafe { libc::geteuid() };
    if !scope.unit.starts_with("se-runtime-")
        || !scope.unit.ends_with(".scope")
        || !valid_group(&scope.cgroup, uid, &scope.unit)
    {
        return Err(input(
            "runtime user scope",
            "recorded native cgroup identity is invalid",
        ));
    }
    // SAFETY: exact native filesystem output for the fixed kernel cgroup mount.
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: literal terminated mount name and writable native statfs storage.
    if unsafe { libc::statfs(c"/sys/fs/cgroup".as_ptr(), &mut filesystem) } != 0
        || filesystem.f_type != 0x6367_7270
    {
        return Err(input(
            "runtime user scope",
            "the unified cgroup mount is unreadable",
        ));
    }
    let path = Path::new("/sys/fs/cgroup")
        .join(scope.cgroup.trim_start_matches('/'))
        .join("cgroup.events");
    match fs::read_to_string(path) {
        Ok(events) if events.len() <= 4096 => match events
            .lines()
            .find_map(|line| line.strip_prefix("populated "))
        {
            Some("0") => Ok(true),
            Some("1") => Ok(false),
            _ => Err(input(
                "runtime user scope",
                "native populated state is unreadable",
            )),
        },
        Ok(_) => Err(input(
            "runtime user scope",
            "native cgroup event extent exceeds its bound",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(input("runtime user scope", &error.to_string())),
    }
}
