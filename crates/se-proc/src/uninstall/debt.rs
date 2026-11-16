//! Persistent exact-object cleanup custody. Core stores this bounded record in
//! its protected install/uninstall journal; a filename alone never grants deletion.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UninstallHelperCleanup {
    version: u32,
    #[serde(with = "crate::checkpoint::native_path")]
    root: PathBuf,
    #[serde(with = "crate::checkpoint::native_path")]
    path: PathBuf,
    pid: u32,
    #[serde(with = "crate::checkpoint::decimal::u64")]
    creation_filetime: u64,
    file: FileId,
    digest: [u8; 32],
    #[serde(default)]
    script: Option<ScriptCustody>,
    // Version 2 requires this field even when its explicit value is null.
    #[serde(deserialize_with = "Option::deserialize")]
    directory: Option<staging::DirectoryCustody>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ScriptCustody {
    #[serde(with = "crate::checkpoint::native_path")]
    pub path: PathBuf,
    pub file: FileId,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelperCleanupOutcome {
    Removed,
    AlreadyAbsent,
    StillRunning,
}
impl UninstallHelperCleanup {
    pub const RECORD_NAME: &'static str = "uninstall-helper-cleanup.json";

    // Capture the newly created empty object before copying any executable
    // bytes. Version 3 may retire a partial copy by its creation identity;
    // version 2 still requires the original completed-image digest.
    pub(super) fn created(
        files: &NativeStateFiles,
        path: PathBuf,
        file: &File,
        digest: [u8; 32],
        directory: Option<staging::DirectoryCustody>,
        script: ScriptCustody,
    ) -> Result<Self> {
        let creator = native::current_process()?;
        Ok(Self {
            version: 3,
            root: files.root().to_owned(),
            path,
            // SAFETY: querying this process identifier has no mutable inputs.
            pid: unsafe { GetCurrentProcessId() },
            creation_filetime: crate::windows_native::process_start(creator.as_raw_handle())
                .map_err(|e| error(e.operation, e.source))?,
            file: native::file_id(file)?,
            digest,
            script: Some(script),
            directory,
        })
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn directory_path(&self) -> Option<&Path> {
        self.directory.as_ref().map(|d| d.path.as_path())
    }
    /// Store only in the protected core journal; bytes are data, not authority.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let bytes = serde_json::to_vec(self)
            .map_err(|e| error("encode helper cleanup custody", io::Error::other(e)))?;
        if bytes.len() > 256 * 1024 {
            return Err(refuse(
                "encode helper cleanup custody",
                "record capacity exceeded",
            ));
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > 256 * 1024 {
            return Err(refuse(
                "decode helper cleanup custody",
                "record capacity exceeded",
            ));
        }
        let value: Self = serde_json::from_slice(bytes)
            .map_err(|e| error("decode helper cleanup custody", io::Error::other(e)))?;
        if !matches!(value.version, 2 | 3) || value.pid == 0 || value.creation_filetime == 0 {
            return Err(refuse(
                "decode helper cleanup custody",
                "unsupported or incomplete native custody",
            ));
        }
        Ok(value)
    }
    /// Invoke on the next install/uninstall from the protected core journal.
    /// Replacements and unreadable process/file facts refuse without deleting.
    pub fn cleanup(&self, files: &NativeStateFiles) -> Result<HelperCleanupOutcome> {
        self.validate_paths(files)?;
        // SAFETY: numeric lookup obtains query/synchronize access only; no signal,
        // inheritance or process mutation occurs.
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                self.pid,
            )
        };
        if raw.is_null() {
            let cause = io::Error::last_os_error();
            if cause.raw_os_error() != Some(ERROR_INVALID_PARAMETER as i32) {
                return Err(error("read pending helper process", cause));
            }
        } else {
            let process = native::handle(raw, "pin pending helper process")?;
            let start = crate::windows_native::process_start(process.as_raw_handle())
                .map_err(|e| error(e.operation, e.source))?;
            if start == self.creation_filetime && !native::exited(&process)? {
                return Ok(HelperCleanupOutcome::StillRunning);
            }
        }
        let directory_pin = match self
            .directory
            .as_ref()
            .map(staging::verify_directory)
            .transpose()
        {
            Ok(pin) => pin,
            Err(cause) if matches!(cause.source.raw_os_error(), Some(code) if code==ERROR_FILE_NOT_FOUND as i32 || code==ERROR_PATH_NOT_FOUND as i32) =>
            {
                if let Some(directory) = &self.directory {
                    native::absent_name(&directory.path)?;
                }
                native::absent_name(&self.path)?;
                if let Some(script) = &self.script {
                    native::absent_name(&script.path)?;
                }
                return Ok(HelperCleanupOutcome::AlreadyAbsent);
            }
            Err(cause) => return Err(cause),
        };
        let digest = (self.version == 2).then_some(self.digest);
        let removed = retire_created(files, &self.path, self.file, digest)?;
        let script_removed = match &self.script {
            Some(script) => retire_created(files, &script.path, script.file, None)?,
            None => false,
        };
        drop(directory_pin);
        if let Some(directory) = &self.directory {
            staging::cleanup_directory(directory)?;
        }
        Ok(if removed || script_removed {
            HelperCleanupOutcome::Removed
        } else {
            HelperCleanupOutcome::AlreadyAbsent
        })
    }
    fn validate_paths(&self, files: &NativeStateFiles) -> Result<()> {
        let name = self.path.file_name().and_then(|v| v.to_str()).unwrap_or("");
        let suffix = name
            .strip_prefix(".se-stage-")
            .and_then(|v| v.strip_suffix(".exe"));
        if self.root != files.root()
            || !match &self.directory {
                None => self.path.parent() == Some(files.root()),
                Some(dir) => {
                    dir.path.parent() == Some(files.root())
                        && self.path.parent() == Some(dir.path.as_path())
                        && dir
                            .path
                            .file_name()
                            .and_then(|n| n.to_str())
                            .and_then(|n| n.strip_prefix(".se-uninstall-"))
                            .is_some_and(|n| {
                                n.len() == 32 && n.bytes().all(|b| b.is_ascii_hexdigit())
                            })
                }
            }
            || !suffix.is_some_and(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(refuse(
                "retire staged uninstall helper",
                "exact immediate staging path under held root required",
            ));
        }
        if let Some(script) = &self.script {
            let valid = script
                .path
                .file_name()
                .and_then(|v| v.to_str())
                .and_then(|v| v.strip_prefix(".se-stage-"))
                .and_then(|v| v.strip_suffix(".ps1"))
                .is_some_and(|v| v.len() == 32 && v.bytes().all(|b| b.is_ascii_hexdigit()));
            if self.version != 3 || script.path.parent() != self.path.parent() || !valid {
                return Err(refuse(
                    "retire staged uninstall script",
                    "exact immediate script creation path required",
                ));
            }
        }
        Ok(())
    }
}

// Version 3 records creation identity before any bytes are written. A partial
// input is ours to retire; another file at the same path remains untouched.
fn retire_created(
    files: &NativeStateFiles,
    path: &Path,
    identity: FileId,
    digest: Option<[u8; 32]>,
) -> Result<bool> {
    let result = (|| {
        let Some(checked) = files.readback(path).map_err(custody)? else {
            native::absent_name(path)?;
            return Ok(false);
        };
        let mut file = native::open_image(path, false)?;
        if native::file_id(&checked)? != native::file_id(&file)?
            || native::file_id(&file)? != identity
            || match digest {
                Some(expected) => native::digest(&mut file)? != expected,
                None => false,
            }
        {
            return Err(refuse(
                "retire staged uninstall input",
                "staging name was replaced; replacement preserved",
            ));
        }
        native::unlink(&file, true)?;
        native::absent_name(path)?;
        Ok(true)
    })();
    result.map_err(|mut cause: UninstallNativeError| {
        cause.pending_paths.push(path.to_owned());
        cause
    })
}
