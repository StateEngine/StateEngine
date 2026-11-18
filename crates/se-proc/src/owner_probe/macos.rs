use super::*;
pub(super) mod ancestry;
use std::{
    mem::{size_of, zeroed},
    ptr,
};

pub(crate) fn boot() -> Result<BootIdentity> {
    let mut mib = [libc::CTL_KERN, libc::KERN_BOOTTIME];
    // SAFETY: native POD output accepts an all-zero initialization.
    let mut time: libc::timeval = unsafe { zeroed() };
    let mut size = size_of::<libc::timeval>();
    // SAFETY: native boot-time MIB, correctly sized timeval output, and no write buffer.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            (&mut time as *mut libc::timeval).cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(native("read boot identity", io::Error::last_os_error()));
    }
    if size != size_of::<libc::timeval>() {
        return Err(refuse("read boot identity", "short native boot result"));
    }
    if time.tv_sec < 0 || !(0..1_000_000).contains(&time.tv_usec) {
        return Err(refuse("read boot identity", "invalid native boot timeval"));
    }
    Ok(BootIdentity::MacOs {
        seconds: time.tv_sec,
        microseconds: time.tv_usec,
    })
}
pub(crate) fn boot_session() -> Result<se_types::BootId> {
    let mut bytes = [0_u8; 37];
    let mut size = bytes.len();
    // SAFETY: static sysctl name, correctly sized output buffer, and no write.
    if unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(native("read boot session UUID", io::Error::last_os_error()));
    }
    if size != bytes.len() || bytes[36] != 0 {
        return Err(refuse("read boot session UUID", "invalid native UUID size"));
    }
    let id = std::str::from_utf8(&bytes[..36])
        .map_err(|_| refuse("read boot session UUID", "invalid UUID encoding"))?;
    let boot = se_types::BootId::new(format!("macos:{}", id.to_ascii_lowercase()))
        .map_err(|_| refuse("read boot session UUID", "invalid UUID encoding"))?;
    if !crate::identity::macos_boot_session(&boot) {
        return Err(refuse("read boot session UUID", "invalid native UUID"));
    }
    Ok(boot)
}
fn info(pid: ProcessId) -> Result<libc::proc_bsdinfo> {
    if pid.0 == 0 || pid.0 > i32::MAX as u32 {
        return Err(refuse("read owner ancestry", "invalid process ID"));
    }
    // SAFETY: native POD output accepts an all-zero initialization.
    let mut info: libc::proc_bsdinfo = unsafe { zeroed() };
    let wanted = size_of::<libc::proc_bsdinfo>() as i32;
    // SAFETY: positive PID and correctly sized aligned BSD process-info output.
    if unsafe {
        libc::proc_pidinfo(
            pid.0 as i32,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            wanted,
        )
    } != wanted
    {
        return Err(native("read owner ancestry", io::Error::last_os_error()));
    }
    Ok(info)
}
pub(super) fn owner(pid: ProcessId) -> Result<NativeOwner> {
    let info = info(pid)?;
    Ok(NativeOwner::Unix {
        real_uid: info.pbi_ruid,
        effective_uid: info.pbi_uid,
    })
}
pub(super) fn stamp(pid: ProcessId, boot: &BootIdentity) -> Result<ProcessStamp> {
    let info = info(pid)?;
    // SAFETY: positive native PID selector; failure is preserved as unreadable ancestry.
    let session = unsafe { libc::getsid(pid.0 as i32) };
    if session < 0 {
        return Err(native("read native session", io::Error::last_os_error()));
    }
    Ok(ProcessStamp {
        pid,
        parent: ProcessId(info.pbi_ppid),
        group: ProcessId(info.pbi_pgid),
        session: ProcessId(session as u32),
        boot: boot.clone(),
        start: StartIdentity::MacOs {
            seconds: info.pbi_start_tvsec,
            microseconds: u32::try_from(info.pbi_start_tvusec)
                .map_err(|_| refuse("read owner ancestry", "native start overflow"))?,
        },
    })
}
