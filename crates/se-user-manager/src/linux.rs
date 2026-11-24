//! Linux background lifetime admission. Failure preserves the existing session host.
use super::bus::{Bus, name};
use super::peer::verify as verify_peer;
use super::symbols;
use std::{
    ffi::CStr,
    fs::{self, File},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub(super) const MANAGER: &CStr = c"/org/freedesktop/systemd1";
pub(super) const INTERFACE: &CStr = c"org.freedesktop.systemd1.Manager";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UserScope {
    pub unit: String,
    pub invocation: String,
    pub cgroup: String,
}

pub fn admit(pin: &File, pid: u32, deadline: Instant) -> Result<UserScope, String> {
    // SAFETY: immutable native owner query, independent of process environment.
    let uid = unsafe { libc::geteuid() };
    login_bound(pid, uid)?;
    lingering()?;
    let api = symbols::Api::load().ok_or("The native user-manager library is unavailable")?;
    // Manager discovery never accepts a caller-supplied bus address.
    let address = name(&format!("unix:path=/run/user/{uid}/systemd/private"))?;
    let deadline = admission_deadline(deadline);
    let bus = Bus::connect(&api, &address, deadline, false)?;
    verify_peer(&bus, uid, deadline)?;
    let mut unit_nonce = [0; 16];
    se_state_files::fill_entropy(&mut unit_nonce).map_err(|e| e.to_string())?;
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
                c"org.freedesktop.systemd1.Scope",
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
            return Ok(UserScope {
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
fn login_bound(pid: u32, uid: u32) -> Result<(), String> {
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(|e| e.to_string())?;
    if text.len() > 65536 {
        return Err("The inherited cgroup fact exceeds its bound".into());
    }
    // Only the native user's top-level login scope calls for migration. A unit
    // already below its user manager, or an unclassified placement, is retained.
    let prefix = format!("0::/user.slice/user-{uid}.slice/session-");
    let session = text
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .and_then(|tail| tail.split('/').next())
        .and_then(|unit| unit.strip_suffix(".scope"));
    if session.is_some_and(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric())) {
        Ok(())
    } else {
        Err("The inherited placement is outside an established login scope; it is preserved without claiming a lasting host lifetime".into())
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
pub fn verify(
    unit: &str,
    invocation: &str,
    cgroup: &str,
    pid: u32,
    deadline: Instant,
) -> Result<(), String> {
    lingering()?;
    // SAFETY: immutable native owner query.
    let uid = unsafe { libc::geteuid() };
    if !valid_group(cgroup, uid, unit) || !in_group(pid, cgroup)? {
        return Err("The exact runtime is outside its admitted user scope".into());
    }
    let api = symbols::Api::load().ok_or("The native user-manager library became unavailable")?;
    let address = name(&format!("unix:path=/run/user/{uid}/systemd/private"))?;
    let deadline = admission_deadline(deadline);
    let bus = Bus::connect(&api, &address, deadline, false)?;
    verify_peer(&bus, uid, deadline)?;
    let request = bus.request(MANAGER, INTERFACE, c"GetUnit")?;
    request.string(b's', &name(unit)?)?;
    let path = name(&bus.call(&request)?.read_string(b'o')?)?;
    let observed_invocation = bus
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
            c"org.freedesktop.systemd1.Scope",
            c"ControlGroup",
            c"s",
        )?
        .read_string(b's')?;
    if se_types::hex_lower(&observed_invocation) != invocation || group != cgroup {
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
pub(super) fn in_group(pid: u32, expected: &str) -> Result<bool, String> {
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup")).map_err(|e| e.to_string())?;
    if text.len() > 65536 {
        return Err("The native cgroup fact exceeds its bound".into());
    }
    Ok(text
        .lines()
        .any(|line| line.strip_prefix("0::") == Some(expected)))
}
pub fn pin_launcher(pid: i32) -> Result<File, String> {
    // SAFETY: this is the retained, unreaped direct child; PIDFDs prevent delayed manager requests from attaching a reused PID.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd < 0 {
        return Err(format!(
            "native launcher pin is unavailable: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: successful pidfd_open transferred this unique descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}
/// Observe only the recorded unit's kernel cgroup after exact host shutdown.
/// This never signals a unit or obtains authority over any process in it.
pub fn scope_empty(unit: &str, cgroup: &str) -> Result<bool, String> {
    // SAFETY: immutable native owner query.
    let uid = unsafe { libc::geteuid() };
    if !unit.starts_with("se-runtime-")
        || !unit.ends_with(".scope")
        || !valid_group(cgroup, uid, unit)
    {
        return Err("recorded native cgroup identity is invalid".into());
    }
    // SAFETY: exact native filesystem output for the fixed kernel cgroup mount.
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: literal terminated mount name and writable native statfs storage.
    if unsafe { libc::statfs(c"/sys/fs/cgroup".as_ptr(), &mut filesystem) } != 0
        || filesystem.f_type != 0x6367_7270
    {
        return Err("the unified cgroup mount is unreadable".into());
    }
    let path = Path::new("/sys/fs/cgroup")
        .join(cgroup.trim_start_matches('/'))
        .join("cgroup.events");
    match fs::read_to_string(path) {
        Ok(events) if events.len() <= 4096 => match events
            .lines()
            .find_map(|line| line.strip_prefix("populated "))
        {
            Some("0") => Ok(true),
            Some("1") => Ok(false),
            _ => Err("native populated state is unreadable".into()),
        },
        Ok(_) => Err("native cgroup event extent exceeds its bound".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(error.to_string()),
    }
}
