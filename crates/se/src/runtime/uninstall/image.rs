use super::*;
#[cfg(not(windows))]
pub(super) fn remove_image(
    _cx: &Bootstrap,
    _plan: &ValidatedUninstallPlan,
    file: &UninstallFile,
    _record_digest: [u8; 32],
    _completion: Option<super::super::uninstall_completion::Request>,
    _achieved: se_core::ops::UninstallOutput,
) -> Result<FileEffect> {
    Ok(remove_file(file))
}
#[cfg(windows)]
pub(super) fn remove_image(
    cx: &Bootstrap,
    plan: &ValidatedUninstallPlan,
    file: &UninstallFile,
    record_digest: [u8; 32],
    completion: Option<super::super::uninstall_completion::Request>,
    achieved: se_core::ops::UninstallOutput,
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
    let receiver = completion.is_some();
    let bytes = serde_json::to_vec(&crate::runtime::handoff::Plan {
        installation: plan.as_untrusted().clone(),
        record_sha256: Sha256::from_bytes(record_digest).hex(),
        completion,
        achieved,
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
    super::super::uninstall_completion::mark_started(receiver);
    crate::runtime::helper_cleanup::verify(&cx.home, &receipt.helper_cleanup)?;
    Ok(file_effect(
        &file.path,
        FileOutcome::Pending,
        WitnessState::Unknown,
        &format!(
            "authorized helper PID {} at {} awaits actual parent exit; verify post-exit absence of image {}, record {}, helper {}{}",
            receipt.helper.pid,
            receipt.pending_helper.display(),
            receipt.pending_image.display(),
            cx.home.join("standalone-install.json").display(),
            receipt.helper_cleanup.path().display(),
            receipt
                .helper_cleanup
                .directory_path()
                .map(|path| format!(", staging directory {}", path.display()))
                .unwrap_or_default()
        ),
    ))
}
