//! Copy and pin the admitted executable before starting the native carrier.
use super::*;
use std::os::windows::fs::OpenOptionsExt;

pub(super) struct Helper {
    path: PathBuf,
    identity: FileId,
    digest: [u8; 32],
    reader: File,
    renamed: bool,
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
                renamed: false,
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
    pub(super) fn remove(&mut self) -> Result<()> {
        let result = (|| {
            if native::file_id(&self.reader)? != self.identity {
                return Err(refuse("remove uninstall helper", "helper identity changed"));
            }
            if !self.renamed {
                if native::digest(&mut self.reader)? != self.digest {
                    return Err(refuse("remove uninstall helper", "helper contents changed"));
                }
                match native::unlink(&self.reader, true) {
                    Ok(()) => return native::absent_name(&self.path),
                    Err(cause)
                        if matches!(cause.source.raw_os_error(),
                        Some(code) if code == ERROR_ACCESS_DENIED as i32 || code == ERROR_SHARING_VIOLATION as i32) =>
                        {}
                    Err(cause) => return Err(cause),
                }
                rename_stream(&self.reader)?;
                self.renamed = true;
            }
            let empty = native::open_image(&self.path, false)?;
            if native::file_id(&empty)? != self.identity {
                return Err(refuse("remove uninstall helper", "helper name changed"));
            }
            native::unlink(&empty, true)?;
            native::absent_name(&self.path)
        })();
        result.map_err(|mut cause| {
            cause.pending_paths.push(self.path.clone());
            cause
        })
    }
}

/// Rename only the pinned helper's data stream; no external name selects it.
fn rename_stream(file: &File) -> Result<()> {
    use std::{
        mem::{offset_of, size_of},
        ptr,
    };
    #[repr(C)]
    struct StreamRename {
        flags: u32,
        root: HANDLE,
        length: u32,
        name: [u16; 33],
    }
    const _: () = assert!(offset_of!(StreamRename, name) == offset_of!(FILE_RENAME_INFO, FileName));
    let mut random = [0; 16];
    crate::fill_entropy(&mut random)
        .map_err(|cause| error("name uninstall helper stream", io::Error::other(cause)))?;
    let stream = format!(":{}", se_types::hex_lower(&random));
    let mut info = StreamRename {
        flags: 0,
        root: ptr::null_mut(),
        length: 66,
        name: [0; 33],
    };
    for (slot, unit) in info.name.iter_mut().zip(stream.encode_utf16()) {
        *slot = unit;
    }
    let reopened = native::handle(
        // SAFETY: the existing pin selects the exact helper object and DELETE is requested explicitly.
        unsafe {
            ReOpenFile(
                file.as_raw_handle(),
                DELETE | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_FLAG_OPEN_REPARSE_POINT,
            )
        },
        "reopen uninstall helper stream",
    )?;
    // SAFETY: native buffer layout and byte length match FILE_RENAME_INFO and contain a bounded stream name.
    if unsafe {
        SetFileInformationByHandle(
            reopened.as_raw_handle(),
            FileRenameInfo,
            (&raw const info).cast(),
            size_of::<StreamRename>() as u32,
        )
    } == 0
    {
        return Err(native::last("rename uninstall helper stream"));
    }
    Ok(())
}
