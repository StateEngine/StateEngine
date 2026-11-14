#![cfg(target_os = "macos")]

use serde_json::json;
use std::{collections::BTreeSet, io, mem, path::PathBuf};

// Observation only: this records the native permission boundary, not a product verdict.
#[test]
fn record_native_owner_ancestry() -> Result<(), Box<dyn std::error::Error>> {
    let mut pid = std::process::id();
    let mut seen = BTreeSet::new();
    let mut observations = Vec::new();
    while pid != 0 && seen.len() < 4096 && seen.insert(pid) {
        // SAFETY: both native output structures are POD and correctly sized below.
        let mut full: libc::proc_bsdinfo = unsafe { mem::zeroed() };
        // SAFETY: native POD output.
        let mut short: libc::proc_bsdshortinfo = unsafe { mem::zeroed() };
        // SAFETY: live numeric PID selector and a correctly sized aligned output buffer.
        let full_bytes = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                libc::PROC_PIDTBSDINFO,
                0,
                (&mut full as *mut libc::proc_bsdinfo).cast(),
                mem::size_of_val(&full) as i32,
            )
        };
        let full_error = (full_bytes != mem::size_of_val(&full) as i32)
            .then(|| io::Error::last_os_error().raw_os_error());
        // SAFETY: live numeric PID selector and a correctly sized aligned output buffer.
        let short_bytes = unsafe {
            libc::proc_pidinfo(
                pid as i32,
                libc::PROC_PIDT_SHORTBSDINFO,
                0,
                (&mut short as *mut libc::proc_bsdshortinfo).cast(),
                mem::size_of_val(&short) as i32,
            )
        };
        let short_error = (short_bytes != mem::size_of_val(&short) as i32)
            .then(|| io::Error::last_os_error().raw_os_error());
        // SAFETY: native PID selector only; errors are recorded separately.
        let session = unsafe { libc::getsid(pid as i32) };
        let session_error = (session < 0).then(|| io::Error::last_os_error().raw_os_error());
        observations.push(json!({
            "pid":pid,"full_bytes":full_bytes,"full_errno":full_error,
            "short_bytes":short_bytes,"short_errno":short_error,
            "parent":(short_error.is_none()).then_some(short.pbsi_ppid),
            "real_uid":(short_error.is_none()).then_some(short.pbsi_ruid),
            "effective_uid":(short_error.is_none()).then_some(short.pbsi_uid),
            "session":(session>=0).then_some(session),"session_errno":session_error
        }));
        if short_error.is_some() {
            break;
        }
        pid = short.pbsi_ppid;
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/judge-diagnostics/macos-owner");
    std::fs::create_dir_all(&root)?;
    let document = json!({"observations":observations,"next_pid":pid});
    std::fs::write(
        root.join("ancestry.json"),
        serde_json::to_vec_pretty(&document)?,
    )?;
    println!("{document}");
    Ok(())
}
