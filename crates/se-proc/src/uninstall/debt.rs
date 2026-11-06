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
    // Version 2 requires this field even when its explicit value is null.
    #[serde(deserialize_with = "Option::deserialize")]
    directory: Option<staging::DirectoryCustody>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelperCleanupOutcome {
    Removed,
    AlreadyAbsent,
    StillRunning,
}
impl UninstallHelperCleanup {
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
        if value.version != 2 || value.pid == 0 || value.creation_filetime == 0 {
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
                return Ok(HelperCleanupOutcome::AlreadyAbsent);
            }
            Err(cause) => return Err(cause),
        };
        let Some(checked) = files.readback(&self.path).map_err(custody)? else {
            drop(directory_pin);
            if let Some(directory) = &self.directory {
                staging::cleanup_directory(directory)?;
            }
            return Ok(HelperCleanupOutcome::AlreadyAbsent);
        };
        let mut file = native::open_image(&self.path, false)?;
        if native::file_id(&checked)? != native::file_id(&file)?
            || native::file_id(&file)? != self.file
            || native::digest(&mut file)? != self.digest
        {
            return Err(refuse(
                "retire staged uninstall helper",
                "helper name was replaced; replacement preserved",
            ));
        }
        native::unlink(&file, true)?;
        native::absent_name(&self.path)?;
        drop(file);
        drop(checked);
        drop(directory_pin);
        if let Some(directory) = &self.directory {
            staging::cleanup_directory(directory)?;
        }
        Ok(HelperCleanupOutcome::Removed)
    }
}
