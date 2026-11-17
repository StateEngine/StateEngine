//! Copy and pin the admitted executable before starting the native carrier.
use super::*;
use std::os::windows::fs::OpenOptionsExt;

pub(super) struct Helper {
    path: PathBuf,
    identity: FileId,
    digest: [u8; 32],
    reader: File,
}
impl Helper {
    pub(super) fn create(
        files: &NativeStateFiles,
        elevated: bool,
        image: &mut File,
        expected: [u8; 32],
    ) -> Result<Self> {
        let mut staged = files.create_staging(files.root()).map_err(custody)?;
        let path = staged.path.with_extension("exe");
        let preparation = (|| {
            let identity = native::file_id(&staged.file)?;
            image
                .rewind()
                .map_err(|cause| error("rewind uninstall helper source", cause))?;
            let copied = io::copy(image, &mut staged.file)
                .map_err(|cause| error("copy uninstall helper", cause))?;
            if copied > 512 * 1024 * 1024 || native::digest(&mut staged.file)? != expected {
                return Err(refuse(
                    "copy uninstall helper",
                    "helper image differs from the admitted executable",
                ));
            }
            staged
                .file
                .sync_all()
                .map_err(|cause| error("flush uninstall helper", cause))?;
            if elevated {
                staging::verify_high(&staged.file, false)?;
            }
            Ok(identity)
        })();
        let identity = preparation.map_err(|mut cause: UninstallNativeError| {
            cause.pending_paths.push(staged.path.clone());
            cause
        })?;
        drop(staged.file);
        files
            .publish_no_replace(&staged.path, &path)
            .map_err(|cause| {
                let mut cause = custody(cause);
                cause.pending_paths.push(staged.path.clone());
                cause
            })?;
        let result = (|| {
            let mut reader = File::options()
                .read(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&path)
                .map_err(|cause| error("pin uninstall helper", cause))?;
            if native::file_id(&reader)? != identity || native::digest(&mut reader)? != expected {
                return Err(refuse(
                    "pin uninstall helper",
                    "helper identity or bytes changed",
                ));
            }
            Ok(Self {
                path: path.clone(),
                identity,
                digest: expected,
                reader,
            })
        })();
        result.map_err(|mut cause| {
            cause.pending_paths.push(path);
            cause
        })
    }
    pub(super) fn path(&self) -> &Path {
        &self.path
    }
    pub(super) fn remove(mut self) -> Result<()> {
        let result = (|| {
            if native::file_id(&self.reader)? != self.identity
                || native::digest(&mut self.reader)? != self.digest
            {
                return Err(refuse(
                    "remove uninstall helper",
                    "helper identity or bytes changed",
                ));
            }
            native::unlink(&self.reader, true)?;
            native::absent_name(&self.path)
        })();
        result.map_err(|mut cause| {
            cause.pending_paths.push(self.path);
            cause
        })
    }
}
