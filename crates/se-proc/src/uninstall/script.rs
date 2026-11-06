//! Readable interpreter input stays immutable without denying the interpreter's
//! ordinary read sharing. Cleanup re-admits the original native file identity.
use super::*;
use crate::OwnedFile;
use std::os::windows::fs::OpenOptionsExt;

pub(super) struct Script {
    path: PathBuf,
    identity: FileId,
    digest: [u8; 32],
    reader: Option<File>,
}
impl Script {
    pub(super) fn create(files: &NativeStateFiles, elevated: bool) -> Result<Self> {
        let mut staged = files.create_staging(files.root()).map_err(custody)?;
        let identity = native::file_id(&staged.file)?;
        let path = staged.path.with_extension("ps1");
        staged
            .file
            .write_all(b"\xef\xbb\xbf")
            .and_then(|()| staged.file.write_all(include_bytes!("carrier.ps1")))
            .and_then(|()| staged.file.sync_all())
            .map_err(|cause| error("write readable uninstall carrier", cause))?;
        if elevated {
            staging::verify_high(&staged.file, false)?;
        }
        use sha2::Digest;
        let mut hash = sha2::Sha256::new();
        hash.update(b"\xef\xbb\xbf");
        hash.update(include_bytes!("carrier.ps1"));
        let digest: [u8; 32] = hash.finalize().into();
        drop(staged.file);
        files
            .publish_no_replace(&staged.path, &path)
            .map_err(custody)?;
        let result = (|| {
            // OwnedFile carries DELETE access. PowerShell opens its -File input
            // without sharing DELETE, so that handle must close before launch.
            // The read-only pin denies both writes and renames until readiness.
            let mut reader = File::options()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&path)
                .map_err(|cause| error("pin readable uninstall carrier", cause))?;
            if native::file_id(&reader)? != identity || native::digest(&mut reader)? != digest {
                return Err(refuse(
                    "pin readable uninstall carrier",
                    "original script identity or bytes changed",
                ));
            }
            Ok(Self {
                path: path.clone(),
                identity,
                digest,
                reader: Some(reader),
            })
        })();
        result.map_err(|cause| pending(cause, &path))
    }
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn remove(mut self) -> Result<()> {
        drop(self.reader.take());
        // Releasing the read pin permits DELETE access again. A replacement,
        // even with identical bytes, is preserved rather than adopted as ours.
        let result = (|| {
            let script = OwnedFile::open(&self.path)
                .map_err(custody)?
                .ok_or_else(|| {
                    refuse(
                        "remove readable uninstall carrier",
                        "original script disappeared",
                    )
                })?;
            let guard = script.uninstall_custody().map_err(custody)?;
            if native::file_id(&guard)? != self.identity {
                return Err(refuse(
                    "remove readable uninstall carrier",
                    "script was replaced; replacement preserved",
                ));
            }
            drop(guard);
            script.remove(self.digest).map_err(custody)
        })();
        result.map_err(|cause| pending(cause, &self.path))
    }
}
fn pending(mut cause: UninstallNativeError, path: &Path) -> UninstallNativeError {
    cause.pending_paths.push(path.to_owned());
    cause
}

#[cfg(test)]
#[path = "../../tests/support/uninstall_readable_script.rs"]
mod judges;
