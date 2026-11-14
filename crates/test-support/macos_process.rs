//! Independent Darwin kernel facts for native process fixture comparisons.
use se_proc::{BootIdentity, MachineId, ProcessId, ProcessIdentity, StartIdentity};
use std::{
    ffi::OsString,
    mem::{size_of, zeroed},
    os::unix::ffi::OsStringExt,
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub(crate) fn bsd(pid: u32) -> Result<libc::proc_bsdinfo> {
    // SAFETY: the native POD output is aligned and its full size is supplied.
    let mut value: libc::proc_bsdinfo = unsafe { zeroed() };
    let size = i32::try_from(size_of::<libc::proc_bsdinfo>())?;
    // SAFETY: only our retained positive child PID is selected, with writable output.
    let count = unsafe {
        libc::proc_pidinfo(
            i32::try_from(pid)?,
            libc::PROC_PIDTBSDINFO,
            // Darwin searches the zombie table only when this argument is nonzero.
            1,
            (&mut value as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if count != size {
        return Err(format!(
            "outside BSD read: {count}/{size}: {}",
            std::io::Error::last_os_error()
        )
        .into());
    }
    assert_eq!(value.pbi_pid, pid);
    Ok(value)
}
pub(crate) fn outside(pid: u32, machine: MachineId) -> Result<ProcessIdentity> {
    let before = bsd(pid)?;
    let mut bytes = vec![0_u8; 4096];
    // SAFETY: retained native PID and bounded writable path storage.
    let count = unsafe {
        libc::proc_pidpath(
            i32::try_from(pid)?,
            bytes.as_mut_ptr().cast(),
            bytes.len() as u32,
        )
    };
    assert!(count > 0 && (count as usize) < bytes.len());
    bytes.truncate(
        bytes
            .iter()
            .position(|b| *b == 0)
            .ok_or("outside path lacks terminator")?,
    );
    let mut mib = [libc::CTL_KERN, libc::KERN_BOOTTIME];
    // SAFETY: native POD output; sysctl fills the exact writable timeval size.
    let mut boot: libc::timeval = unsafe { zeroed() };
    let mut length = size_of::<libc::timeval>();
    assert_eq!(
        // SAFETY: read-only kernel MIB, correctly sized aligned output, no input buffer.
        unsafe {
            libc::sysctl(
                mib.as_mut_ptr(),
                2,
                (&mut boot as *mut libc::timeval).cast(),
                &mut length,
                std::ptr::null_mut(),
                0,
            )
        },
        0
    );
    assert_eq!(length, size_of::<libc::timeval>());
    let after = bsd(pid)?;
    assert_eq!(
        (before.pbi_start_tvsec, before.pbi_start_tvusec),
        (after.pbi_start_tvsec, after.pbi_start_tvusec)
    );
    Ok(ProcessIdentity {
        machine,
        boot: BootIdentity::MacOs {
            seconds: boot.tv_sec,
            microseconds: boot.tv_usec,
        },
        pid: ProcessId(pid),
        start: StartIdentity::MacOs {
            seconds: before.pbi_start_tvsec,
            microseconds: u32::try_from(before.pbi_start_tvusec)?,
        },
        image: OsString::from_vec(bytes).into(),
    })
}
