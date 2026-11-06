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
    _cx: &Bootstrap,
    _plan: &ValidatedUninstallPlan,
    file: &UninstallFile,
    _record_digest: [u8; 32],
    completion: Option<super::super::uninstall_completion::Request>,
    achieved: se_core::ops::UninstallOutput,
    carrier: Option<se_proc::NativeUninstallCarrier>,
) -> Result<FileEffect> {
    let Some(carrier) = carrier else {
        // The ordinary native removal reader distinguishes absent from unreadable
        // and preserves a replacement which appeared after recovery admission.
        let observation = OwnedFile::open(Path::new(&file.path)).map_err(native_error)?;
        if observation.is_some() {
            return Err(conflict(&file.path));
        }
        return Ok(file_effect(
            &file.path,
            FileOutcome::AlreadyAbsent,
            WitnessState::Witnessed,
            "archive recovery: installed image natively absent; working archive image is preserved",
        ));
    };
    let mut image = OwnedFile::open(Path::new(&file.path))
        .map_err(native_error)?
        .ok_or_else(|| conflict(&file.path))?;
    if image.sha256().map_err(native_error)? != digest_bytes(&file.sha256)? {
        return Err(conflict(&file.path));
    }
    let receiver = completion.is_some();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "completion": completion,
        "achieved": se_core::ops::AnyOutput::from(achieved),
    }))
    .map_err(|error| invalid("cannot encode carrier completion report").with_cause(error))?;
    carrier.authorize(&bytes).map_err(|error| {
        se_core::scope::unreadable(
            "Windows uninstall carrier authorization",
            &error.to_string(),
        )
    })?;
    super::super::uninstall_completion::mark_started(receiver);
    Ok(file_effect(
        &file.path,
        FileOutcome::Pending,
        WitnessState::Unknown,
        "authenticated system carrier awaits actual parent exit; image and record removal require outside completion readback",
    ))
}
