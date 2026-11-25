//! A pinned native carrier consumes only inherited, already admitted objects.
//! Preparation is read-only for the installation; authorization follows effects.
use super::*;
use se_state_files::{NativeInstallationClaim, OwnedFile};
use std::os::windows::ffi::OsStrExt;

#[derive(serde::Serialize)]
struct Entry {
    handle: u64,
    path: PathBuf,
    kind: &'static str,
    identity: String,
    sha256: Option<String>,
}
pub struct NativeUninstallCarrier {
    process: OwnedHandle,
    authorize: File,
    report: File,
    nonce: [u8; 32],
    deadline: u64,
}
fn entry(file: &File, path: &Path, kind: &'static str, sha: Option<[u8; 32]>) -> Result<Entry> {
    let id = se_native_path::windows::file::file_id(file)
        .map_err(|cause| error("identify uninstall carrier object", cause))?;
    Ok(Entry {
        handle: file.as_raw_handle() as usize as u64,
        path: path.to_owned(),
        kind,
        identity: format!("{:016x}:{}", id.volume, se_types::hex_lower(&id.index)),
        sha256: sha.map(|value| se_types::hex_lower(&value)),
    })
}
impl NativeUninstallCarrier {
    /// Core has admitted the original record, account and finite directory list.
    /// Nothing here accepts executable text or an alternate image to remove.
    pub fn prepare(
        files: &NativeStateFiles,
        claim: &NativeInstallationClaim,
        record: &OwnedFile,
        record_path: &Path,
        record_digest: [u8; 32],
        directories: &[String],
    ) -> Result<Self> {
        let deadline = clock() + 90000;
        let mut staging = if staging::elevated()? {
            Some(staging::Staging::create(files)?)
        } else {
            None
        };
        let script_files = staging.as_ref().map_or(files, |stage| stage.files());
        // Retire both empty names before writing any private data. File-backed
        // envelopes cannot block the CLI on an unavailable interpreter's stdin.
        let report = fresh_staging(script_files)?;

        let parent = native::current_process()?;
        let image = native::process_image(&parent)?;
        let mut target = native::open_image(&image, false)?;
        let digest = native::digest(&mut target)?;
        let record = record.uninstall_custody().map_err(custody)?;
        let claim = claim.uninstall_custody().map_err(custody)?;
        let (read, write) = native::pipe()?;
        let (ready, ready_write) = native::pipe()?;
        let objects = [
            (&target, image.as_path(), "image", Some(digest)),
            (&record, record_path, "record", Some(record_digest)),
        ];
        let (mut entries, mut owned) = build_entries(objects, directories, &staging)?;
        // Keep both original parent directories available for native flushes.
        for path in [image.parent(), record_path.parent()].into_iter().flatten() {
            let file = se_state_files::state_files::windows::effects::uninstall_directory(path)
                .map_err(custody)?
                .ok_or_else(|| refuse("prepare uninstall carrier", "original parent absent"))?;
            let copy = native::duplicate_same(file.as_raw_handle(), true)?;
            let mut observed = entry(&file, path, "flush", None)?;
            observed.handle = copy.as_raw_handle() as usize as u64;
            entries.push(observed);
            owned.push(copy);
        }
        let inherited = [
            parent.as_raw_handle(),
            claim.as_raw_handle(),
            read.as_raw_handle(),
            ready_write.as_raw_handle(),
            report.as_raw_handle(),
        ];
        let mut control = Vec::new();
        for handle in inherited {
            control.push(native::duplicate_same(handle, true)?);
        }
        let mut random = [0; 32];
        se_state_files::fill_entropy(&mut random)
            .map_err(|cause| error("prepare carrier authorization", io::Error::other(cause)))?;
        let nonce = se_types::hex_lower(&random);
        let plan_file = write_plan(script_files, &control, &nonce, deadline, &entries)?;
        let input = native::duplicate(plan_file.as_raw_handle(), FILE_GENERIC_READ, true)?;
        let handles: Vec<_> = owned
            .iter()
            .chain(&control)
            .map(AsRawHandle::as_raw_handle)
            .collect();
        let environment = cleanup::environment(script_files.root())?;
        let mut diagnostic = fresh_staging(script_files)?;
        let helper =
            match helper::Helper::create(script_files, staging.is_some(), &mut target, digest) {
                Ok(helper) => helper,
                Err(mut failure) => {
                    cleanup_artifacts(&mut failure, &mut None, &mut staging);
                    return Err(failure);
                }
            };
        let helper_path = helper.path().to_owned();
        let mut helper = Some(helper);
        let process = match spawn_carrier(&helper_path, &input, &handles, &environment, &diagnostic)
        {
            Ok(process) => process,
            Err(mut failure) => {
                cleanup_artifacts(&mut failure, &mut helper, &mut staging);
                return Err(failure);
            }
        };
        drop(input);
        drop(plan_file);
        drop(owned);
        drop(control);
        let preparation = await_readiness(&process, ready, random, &mut helper, &mut staging);
        if let Err(failure) = preparation {
            return Err(report_preparation_failure(
                &process,
                failure,
                &mut helper,
                &mut staging,
                &helper_path,
                &mut diagnostic,
            ));
        }
        Ok(Self {
            process,
            authorize: write,
            report,
            nonce: random,
            deadline,
        })
    }
    /// The parent retains its claims until actual exit. EOF without this exact
    /// nonce never authorizes deletion, even if the parent crashes.
    pub fn authorize(mut self, report: &[u8]) -> Result<()> {
        check_deadline(self.deadline)?;
        if native::exited(&self.process)? {
            return Err(refuse(
                "authorize uninstall carrier",
                "prepared system carrier exited",
            ));
        }
        if report.len() > 2 * 1024 * 1024 {
            return Err(refuse(
                "authorize uninstall carrier",
                "report exceeds two MiB",
            ));
        }
        let report: serde_json::Value = serde_json::from_slice(report)
            .map_err(|cause| error("encode carrier report", io::Error::other(cause)))?;
        let mut bytes = serde_json::to_vec(
            &serde_json::json!({"nonce":se_types::hex_lower(&self.nonce),"report":report}),
        )
        .map_err(|cause| error("encode carrier authorization", io::Error::other(cause)))?;
        bytes.push(b'\n');
        if bytes.len() > 2 * 1024 * 1024 {
            return Err(refuse(
                "authorize uninstall carrier",
                "completion envelope exceeds two MiB",
            ));
        }
        self.report
            .write_all(&bytes)
            .and_then(|()| self.report.rewind())
            .map_err(|cause| error("prepare private completion report", cause))?;
        let mut authorization = [0; 33];
        authorization[0] = b'G';
        authorization[1..].copy_from_slice(&self.nonce);
        self.authorize
            .write_all(&authorization)
            .map_err(|cause| error("authorize uninstall carrier", cause))
    }
}

fn fresh_staging(files: &NativeStateFiles) -> Result<File> {
    files
        .retire_empty_staging(files.create_staging(files.root()).map_err(custody)?)
        .map_err(custody)
}

fn build_entries(
    objects: [(&File, &Path, &'static str, Option<[u8; 32]>); 2],
    directories: &[String],
    staging: &Option<staging::Staging>,
) -> Result<(Vec<Entry>, Vec<OwnedHandle>)> {
    let mut owned = Vec::new();
    let mut entries = Vec::new();
    for (file, path, kind, digest) in objects {
        let copy = native::duplicate_same(file.as_raw_handle(), true)?;
        entries.push(entry(
            &File::from(native::duplicate_same(copy.as_raw_handle(), false)?),
            path,
            kind,
            digest,
        )?);
        if let Some(last) = entries.last_mut() {
            last.handle = copy.as_raw_handle() as usize as u64;
        }
        owned.push(copy);
    }
    for path in directories.iter().map(Path::new) {
        if let Some(file) = se_state_files::state_files::windows::effects::uninstall_directory(path)
            .map_err(custody)?
        {
            let copy = native::duplicate_same(file.as_raw_handle(), true)?;
            let mut observed = entry(&file, path, "directory", None)?;
            observed.handle = copy.as_raw_handle() as usize as u64;
            entries.push(observed);
            owned.push(copy);
        }
    }
    if let Some(stage) = staging {
        let copy = native::duplicate_same(stage.pin().as_raw_handle(), true)?;
        let mut observed = entry(stage.pin(), &stage.directory.path, "staging", None)?;
        observed.handle = copy.as_raw_handle() as usize as u64;
        entries.push(observed);
        owned.push(copy);
    }
    Ok((entries, owned))
}

fn write_plan(
    script_files: &NativeStateFiles,
    control: &[OwnedHandle],
    nonce: &str,
    deadline: u64,
    entries: &[Entry],
) -> Result<File> {
    let frame = serde_json::json!({"parent":control[0].as_raw_handle() as usize as u64,
        "claim":control[1].as_raw_handle() as usize as u64,
        "authorize":control[2].as_raw_handle() as usize as u64,
        "ready":control[3].as_raw_handle() as usize as u64,
        "report":control[4].as_raw_handle() as usize as u64,
        "nonce":nonce,"deadline":deadline,"entries":entries});
    let mut plan_file = fresh_staging(script_files)?;
    let mut encoded = serde_json::to_vec(&frame)
        .map_err(|cause| error("encode carrier objects", io::Error::other(cause)))?;
    if encoded.len() > 2 * 1024 * 1024 {
        return Err(refuse(
            "prepare uninstall carrier",
            "object inventory exceeds two MiB",
        ));
    }
    encoded.push(b'\n');
    plan_file
        .write_all(&encoded)
        .and_then(|()| plan_file.rewind())
        .map_err(|cause| error("prepare private carrier envelope", cause))?;
    Ok(plan_file)
}

fn spawn_carrier(
    helper_path: &Path,
    input: &OwnedHandle,
    handles: &[HANDLE],
    environment: &[u16],
    diagnostic: &File,
) -> Result<OwnedHandle> {
    let mut application: Vec<u16> = helper_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut line = vec![u16::from(b'"')];
    line.extend(helper_path.as_os_str().encode_wide());
    line.extend("\" ".encode_utf16());
    line.extend(super::UNINSTALL_CARRIER_ENTRY.encode_utf16());
    line.push(0);
    let process = spawn::command(
        &application,
        &mut line,
        input,
        handles,
        CREATE_NO_WINDOW,
        Some(environment),
        Some(diagnostic),
    )?;
    application.clear();
    Ok(process)
}

fn await_readiness(
    process: &OwnedHandle,
    ready: File,
    random: [u8; 32],
    helper: &mut Option<helper::Helper>,
    staging: &mut Option<staging::Staging>,
) -> Result<()> {
    let until = clock() + 30000;
    let mut ready = ready;
    loop {
        if native::exited(process)? {
            return Err(refuse(
                "prepare uninstall carrier",
                "system carrier exited; installation remains unchanged",
            ));
        }
        if let Some(frame) = native::poll_frame(&mut ready)? {
            if frame[0] != b'R' || frame[1..] != random {
                return Err(refuse(
                    "prepare uninstall carrier",
                    "readiness authentication failed",
                ));
            }
            break;
        }
        if clock() >= until {
            return Err(refuse(
                "prepare uninstall carrier",
                "system carrier readiness deadline; installation remains unchanged",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    helper
        .as_mut()
        .ok_or_else(|| refuse("prepare uninstall carrier", "helper custody missing"))?
        .remove()?;
    helper.take();
    // The carrier retains the exact High directory until it can close
    // its anonymous input, report and diagnostic files after our exit.
    drop(staging.take());
    Ok(())
}

fn report_preparation_failure(
    process: &OwnedHandle,
    mut failure: UninstallNativeError,
    helper: &mut Option<helper::Helper>,
    staging: &mut Option<staging::Staging>,
    helper_path: &Path,
    diagnostic: &mut File,
) -> UninstallNativeError {
    match cancel_preparation(process) {
        Ok(()) => {
            failure.diagnostic = Some(diagnostic_text(diagnostic));
            cleanup_artifacts(&mut failure, helper, staging);
        }
        Err(cause) => {
            failure.cleanup_failures.push(cause);
            if helper.is_some() {
                failure.pending_paths.push(helper_path.to_path_buf());
            }
            if let Some(stage) = &staging {
                failure.pending_paths.push(stage.directory.path.clone());
            }
        }
    }
    failure
}

// A preparation failure must also release the exact child's inherited claims.
// A retained process handle cannot select a reused PID or another interpreter.
fn cancel_preparation(process: &OwnedHandle) -> Result<()> {
    if native::exited(process)? {
        return Ok(());
    }
    // SAFETY: this is the process handle returned by our own CreateProcessW.
    if unsafe { TerminateProcess(process.as_raw_handle(), 78) } == 0 {
        let cause = native::last("cancel unavailable uninstall carrier");
        if !native::exited(process)? {
            return Err(cause);
        }
    }
    // SAFETY: the same retained process handle has synchronize access.
    match unsafe { WaitForSingleObject(process.as_raw_handle(), 5000) } {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(refuse(
            "cancel unavailable uninstall carrier",
            "exact child exit remains unwitnessed; installation remains unchanged",
        )),
        _ => Err(native::last("observe cancelled uninstall carrier")),
    }
}

fn cleanup_artifacts(
    failure: &mut UninstallNativeError,
    helper: &mut Option<helper::Helper>,
    staging: &mut Option<staging::Staging>,
) {
    if let Some(held) = helper.as_mut() {
        let path = held.path().to_owned();
        if let Err(cause) = held.remove() {
            cleanup_failure(failure, cause, &path);
        } else {
            helper.take();
        }
    }
    if let Some(stage) = staging.take() {
        let directory = stage.directory.path.clone();
        drop(stage);
        if let Err(cause) = se_state_files::remove_empty_directory(&directory) {
            cleanup_failure(failure, custody(cause), &directory);
        }
    }
}
fn cleanup_failure(failure: &mut UninstallNativeError, cause: UninstallNativeError, path: &Path) {
    failure.cleanup_failures.push(cause);
    failure.pending_paths.push(path.to_owned());
}

fn diagnostic_text(file: &mut File) -> String {
    const LIMIT: u64 = 65536;
    let result = (|| -> io::Result<Vec<u8>> {
        file.rewind()?;
        let mut bytes = Vec::new();
        file.take(LIMIT + 1).read_to_end(&mut bytes)?;
        Ok(bytes)
    })();
    match result {
        Err(cause) => format!("native stderr unreadable: {cause}"),
        Ok(bytes) if bytes.is_empty() => "native stderr was empty".into(),
        Ok(mut bytes) => {
            let truncated = bytes.len() as u64 > LIMIT;
            bytes.truncate(LIMIT as usize);
            let text = String::from_utf8(bytes).unwrap_or_else(|cause| {
                format!(
                    "non-UTF-8 bytes: {}",
                    se_types::hex_lower(&cause.into_bytes())
                )
            });
            format!(
                "native stderr{}: {text}",
                if truncated {
                    " (first 64 KiB; remainder omitted)"
                } else {
                    ""
                }
            )
        }
    }
}
