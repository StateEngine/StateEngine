use super::*;
#[cfg(not(windows))]
pub(super) fn remove_image(
    _cx: &Bootstrap,
    _plan: &ValidatedUninstallPlan,
    file: &UninstallFile,
    _record_digest: [u8; 32],
) -> Result<FileEffect> {
    Ok(remove_file(file))
}
#[cfg(windows)]
pub(super) fn remove_image(
    cx: &Bootstrap,
    plan: &ValidatedUninstallPlan,
    file: &UninstallFile,
    record_digest: [u8; 32],
) -> Result<FileEffect> {
    use se_proc::{NativeStateFiles, NativeUninstallHandoff, UninstallReady};
    use std::time::{Duration, Instant};
    let mut image = OwnedFile::open(Path::new(&file.path))
        .map_err(native_error)?
        .ok_or_else(|| conflict(&file.path))?;
    let expected = digest_bytes(&file.sha256)?;
    if image.sha256().map_err(native_error)? != expected {
        return Err(conflict(&file.path));
    }
    let files = NativeStateFiles::open(&cx.home).map_err(native_error)?;
    let bytes = serde_json::to_vec(&crate::runtime::handoff::Plan {
        installation: plan.as_untrusted().clone(),
        record_sha256: Sha256::from_bytes(record_digest).hex(),
    })
    .map_err(|e| invalid("cannot encode helper plan").with_cause(e))?;
    let mut helper = NativeUninstallHandoff::start(&files, &bytes, Duration::from_secs(30))
        .map_err(|e| {
            se_core::scope::unreadable(
                "Windows uninstall handoff",
                &format!("{e}; pending artifacts: {:?}", e.pending_paths),
            )
        })?;
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match helper
            .poll_ready()
            .map_err(|e| se_core::scope::unreadable("Windows helper readiness", &e.to_string()))?
        {
            UninstallReady::Ready => break,
            UninstallReady::Pending if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20))
            }
            _ => {
                return Err(se_core::scope::unreadable(
                    "Windows helper readiness",
                    "deadline exhausted; image and staged artifacts remain pending",
                ));
            }
        }
    }
    if image.sha256().map_err(native_error)? != expected {
        return Err(conflict(&file.path));
    }
    let receipt = helper.authorize().map_err(|e| {
        se_core::scope::unreadable("Windows uninstall authorization", &e.to_string())
    })?;
    crate::runtime::helper_cleanup::verify(&cx.home, &receipt.helper_cleanup)?;
    Ok(file_effect(
        &file.path,
        FileOutcome::Pending,
        WitnessState::Unknown,
        &format!(
            "authorized helper PID {} awaits actual parent exit; image deletion and helper cleanup require post-exit outside readback",
            receipt.helper.pid
        ),
    ))
}
