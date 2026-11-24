//! Bind the private manager peer to the system manager's exact user-service PID.
//! User managers may deliberately deny even their owner access to /proc/pid/exe.
use super::{
    bus::{Bus, name},
    linux::{INTERFACE, MANAGER, in_group},
};
use std::{
    ffi::CStr,
    fs::{self, File},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{FileTypeExt, MetadataExt},
    },
    time::Instant,
};

pub(super) fn verify(bus: &Bus<'_>, uid: u32, deadline: Instant) -> Result<(), String> {
    let fd = bus.fd()?;
    // SAFETY: native POD output, initialized by the exact getsockopt call below.
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&credentials) as libc::socklen_t;
    // SAFETY: exact writable native credential extent on the retained socket.
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut size,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if size as usize != std::mem::size_of_val(&credentials)
        || credentials.uid != uid
        || credentials.pid <= 0
    {
        return Err("The private manager peer has a different native owner".into());
    }
    // SAFETY: read-only exact native process reference; this pin grants no signal authority.
    let reference = unsafe { libc::syscall(libc::SYS_pidfd_open, credentials.pid, 0) } as i32;
    if reference < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // SAFETY: successful pidfd_open transferred one unique descriptor.
    let pin = unsafe { File::from_raw_fd(reference) };
    let stat =
        fs::read_to_string(format!("/proc/{}/stat", credentials.pid)).map_err(|e| e.to_string())?;
    let parent = stat
        .rsplit_once(')')
        .and_then(|(_, tail)| tail.split_whitespace().nth(1));
    let group = format!("/user.slice/user-{uid}.slice/user@{uid}.service/init.scope");
    if parent != Some("1") || !in_group(credentials.pid as u32, &group)? {
        return Err("The private peer is outside the native user-manager service".into());
    }
    let manager = system_manager_pid(bus, uid, deadline)?;
    let mut poll = libc::pollfd {
        fd: pin.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: zero-timeout liveness observation on the exact retained manager instance.
    if manager != credentials.pid as u32 || unsafe { libc::poll(&mut poll, 1, 0) } != 0 {
        return Err("The private peer is not the system manager's current user service".into());
    }
    Ok(())
}

fn system_manager_pid(private: &Bus<'_>, uid: u32, deadline: Instant) -> Result<u32, String> {
    let before = system_socket()?;
    let bus = Bus::connect(
        private.api,
        c"unix:path=/run/dbus/system_bus_socket",
        deadline,
        true,
    )?;
    if before != system_socket()? {
        return Err("The protected system bus socket changed".into());
    }
    // The system bus authenticates connection UID and PID. Require the service
    // answering the user-unit query to belong to native root PID 1, not merely
    // a same-user process that claimed a familiar service name.
    if connection(&bus, c"GetConnectionUnixUser")? != 0
        || connection(&bus, c"GetConnectionUnixProcessID")? != 1
    {
        return Err("The system manager service is not native root PID 1".into());
    }
    let request = bus.request(MANAGER, INTERFACE, c"GetUnit")?;
    request.string(b's', &name(&format!("user@{uid}.service"))?)?;
    let path = name(&bus.call(&request)?.read_string(b'o')?)?;
    let pid = bus
        .property(&path, c"org.freedesktop.systemd1.Service", c"MainPID", c"u")?
        .uint()?;
    if connection(&bus, c"GetConnectionUnixUser")? != 0
        || connection(&bus, c"GetConnectionUnixProcessID")? != 1
    {
        return Err("The system manager changed during user-service observation".into());
    }
    Ok(pid)
}
fn connection(bus: &Bus<'_>, member: &CStr) -> Result<u32, String> {
    let request = bus.request_to(
        c"org.freedesktop.DBus",
        c"/org/freedesktop/DBus",
        c"org.freedesktop.DBus",
        member,
    )?;
    request.string(b's', c"org.freedesktop.systemd1")?;
    bus.call(&request)?.uint()
}
fn system_socket() -> Result<(u64, u64), String> {
    for path in ["/run", "/run/dbus"] {
        let entry = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !entry.is_dir()
            || entry.file_type().is_symlink()
            || entry.uid() != 0
            || entry.mode() & 0o022 != 0
        {
            return Err("The system bus directory is not administrator-protected".into());
        }
    }
    let socket = fs::symlink_metadata("/run/dbus/system_bus_socket").map_err(|e| e.to_string())?;
    if !socket.file_type().is_socket() || socket.uid() != 0 {
        return Err("The protected native system bus socket is absent".into());
    }
    Ok((socket.dev(), socket.ino()))
}
