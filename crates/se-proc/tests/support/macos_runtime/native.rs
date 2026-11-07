//! Independent kernel reads used for effects and exact-owned cleanup.
use super::*;
use std::{
    ffi::OsString,
    mem::{size_of, zeroed},
    os::unix::ffi::OsStringExt,
};
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Pin {
    pub identity: ProcessIdentity,
    pub argv: Vec<Vec<u8>>,
}
pub fn bsd(pid: ProcessId) -> Check<Option<libc::proc_bsdinfo>> {
    // SAFETY: aligned native POD, exact output length supplied.
    let mut value: libc::proc_bsdinfo = unsafe { zeroed() };
    let size = i32::try_from(size_of::<libc::proc_bsdinfo>())?;
    // SAFETY: clear this thread's errno before distinguishing native absence.
    unsafe {
        *libc::__error() = 0;
    }
    // SAFETY: positive selected PID; arg=1 includes real zombie records.
    let n = unsafe {
        libc::proc_pidinfo(
            i32::try_from(pid.0)?,
            libc::PROC_PIDTBSDINFO,
            1,
            (&mut value as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if n == size {
        assert_eq!(value.pbi_pid, pid.0);
        return Ok(Some(value));
    }
    let e = std::io::Error::last_os_error();
    if n == 0 && e.raw_os_error() == Some(libc::ESRCH) {
        return Ok(None);
    }
    Err(format!("outside BSD {n}/{size}: {e}").into())
}
pub fn identity(pid: ProcessId) -> Check<ProcessIdentity> {
    let before = bsd(pid)?.ok_or("outside process absent")?;
    let mut path = vec![0u8; 4096];
    // SAFETY: bounded writable buffer for the selected PID's native image.
    let n = unsafe {
        libc::proc_pidpath(
            i32::try_from(pid.0)?,
            path.as_mut_ptr().cast(),
            path.len() as u32,
        )
    };
    if n <= 0 || n as usize >= path.len() {
        return Err("outside image unreadable".into());
    }
    path.truncate(
        path.iter()
            .position(|b| *b == 0)
            .ok_or("outside image lacks NUL")?,
    );
    let mut mib = [libc::CTL_KERN, libc::KERN_BOOTTIME];
    // SAFETY: native POD initialized before a bounded kernel read.
    let mut boot: libc::timeval = unsafe { zeroed() };
    let mut length = size_of::<libc::timeval>();
    // SAFETY: exact read-only kernel MIB and aligned writable timeval output.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            (&mut boot as *mut libc::timeval).cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    assert_eq!(length, size_of::<libc::timeval>());
    let after = bsd(pid)?.ok_or("outside process vanished during read")?;
    assert_eq!(
        (before.pbi_start_tvsec, before.pbi_start_tvusec),
        (after.pbi_start_tvsec, after.pbi_start_tvusec)
    );
    Ok(ProcessIdentity {
        machine: machine()?,
        boot: BootIdentity::MacOs {
            seconds: boot.tv_sec,
            microseconds: boot.tv_usec,
        },
        pid,
        start: StartIdentity::MacOs {
            seconds: before.pbi_start_tvsec,
            microseconds: u32::try_from(before.pbi_start_tvusec)?,
        },
        image: OsString::from_vec(path).into(),
    })
}
fn argv(pid: ProcessId) -> Check<Vec<Vec<u8>>> {
    let mut bytes = vec![0u8; 1024 * 1024];
    let mut length = bytes.len();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, i32::try_from(pid.0)?];
    // SAFETY: native read of this exact PID's argv into bounded writable storage.
    if unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            bytes.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    bytes.truncate(length);
    let argc = i32::from_ne_bytes(bytes.get(..4).ok_or("outside argc missing")?.try_into()?);
    if !(1..=65536).contains(&argc) {
        return Err("outside argc invalid".into());
    }
    let mut at = 4;
    while *bytes.get(at).ok_or("outside exec path truncated")? != 0 {
        at += 1;
    }
    while bytes.get(at) == Some(&0) {
        at += 1;
    }
    let mut args = Vec::new();
    for _ in 0..argc {
        let end = bytes[at..]
            .iter()
            .position(|b| *b == 0)
            .ok_or("outside argv truncated")?
            + at;
        args.push(bytes[at..end].to_vec());
        at = end + 1;
    }
    Ok(args)
}
pub fn pin(pid: ProcessId) -> Check<Pin> {
    let expected = identity(pid)?;
    let args = argv(pid)?;
    assert_eq!(identity(pid)?, expected);
    Ok(Pin {
        identity: expected,
        argv: args,
    })
}
pub fn read_pin(root: &Path, who: &str) -> Check<Pin> {
    Ok(serde_json::from_slice(&fs::read(
        root.join(format!("pin-{who}.json")),
    )?)?)
}
pub fn live(pin: &Pin) -> Check<bool> {
    let Some(value) = bsd(pin.identity.pid)? else {
        return Ok(false);
    };
    let expected = &pin.identity.start;
    if *expected
        != (StartIdentity::MacOs {
            seconds: value.pbi_start_tvsec,
            microseconds: u32::try_from(value.pbi_start_tvusec)?,
        })
    {
        return Ok(false);
    }
    if value.pbi_status == libc::SZOMB {
        return Ok(false);
    }
    if identity(pin.identity.pid)? != pin.identity || argv(pin.identity.pid)? != pin.argv {
        return Err("outside original process changed image or full argv; cleanup refused".into());
    }
    Ok(true)
}
pub fn cleanup(pin: &Pin) -> Check {
    if !live(pin)? {
        return Ok(());
    }
    println!(
        "exact native cleanup: {:?} argv={:?}",
        pin.identity, pin.argv
    );
    // SAFETY: full original birth, boot, image and argv were just reread above.
    if unsafe { libc::kill(i32::try_from(pin.identity.pid.0)?, libc::SIGKILL) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ESRCH) {
            return Err(e.into());
        }
    }
    wait(|| Ok(!live(pin)?))
}
