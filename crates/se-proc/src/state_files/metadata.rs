//! Metadata custody must not close an ordinary descriptor on a live SQLite inode.
use super::*;
use std::fs::Metadata;

pub struct NativeMetadataPin {
    files: NativeStateFiles,
    path: PathBuf,
    #[cfg(not(target_os = "macos"))]
    file: File,
    #[cfg(target_os = "macos")]
    original: Metadata,
}
impl NativeMetadataPin {
    pub(super) fn open(files: &NativeStateFiles, path: &Path) -> Result<Option<Self>> {
        files.check(path)?;
        #[cfg(target_os = "macos")]
        let Some(original) = files.inspect_metadata(path)? else {
            return Ok(None);
        };
        #[cfg(target_os = "linux")]
        let Some(file) = files.directory.pin_metadata(path, &files.root)? else {
            return Ok(None);
        };
        #[cfg(windows)]
        let Some(file) = files.directory.readback(path, &files.root)? else {
            return Ok(None);
        };
        let pin = Self {
            files: NativeStateFiles::open(&files.root)?,
            path: path.into(),
            #[cfg(not(target_os = "macos"))]
            file,
            #[cfg(target_os = "macos")]
            original,
        };
        pin.metadata()?;
        Ok(Some(pin))
    }
    pub fn metadata(&self) -> Result<Metadata> {
        let named = self.files.inspect_metadata(&self.path)?.ok_or_else(|| {
            failure(
                StateFileErrorCode::SourceChanged,
                "database metadata name disappeared",
                &self.path,
            )
        })?;
        #[cfg(target_os = "macos")]
        let held = self.original.clone();
        #[cfg(target_os = "linux")]
        let held = self
            .file
            .metadata()
            .map_err(|e| io_error("inspect retained database metadata", &self.path, e))?;
        #[cfg(unix)]
        let same = {
            use std::os::unix::fs::MetadataExt;
            let same = held.dev() == named.dev() && held.ino() == named.ino();
            #[cfg(target_os = "macos")]
            use std::os::macos::fs::MetadataExt as _;
            #[cfg(target_os = "macos")]
            let same = same
                && held.st_birthtime() == named.st_birthtime()
                && held.st_birthtime_nsec() == named.st_birthtime_nsec();
            same
        };
        #[cfg(windows)]
        let same = {
            let other = self
                .files
                .directory
                .readback(&self.path, &self.files.root)?
                .ok_or_else(|| {
                    failure(
                        StateFileErrorCode::SourceChanged,
                        "database name disappeared",
                        &self.path,
                    )
                })?;
            let a = crate::observe_file_revision(&self.file)
                .map_err(|e| io_error("inspect retained database identity", &self.path, e))?;
            let b = crate::observe_file_revision(&other)
                .map_err(|e| io_error("inspect named database identity", &self.path, e))?;
            a.volume == b.volume && a.file == b.file
        };
        if !same {
            return Err(failure(
                StateFileErrorCode::SourceChanged,
                "database metadata identity changed",
                &self.path,
            ));
        }
        Ok(named)
    }
    pub fn validate_path(&self, path: &Path) -> Result<()> {
        if path != self.path {
            return Err(failure(
                StateFileErrorCode::SourceChanged,
                "database metadata path changed",
                path,
            ));
        }
        self.metadata().map(|_| ())
    }
    pub fn identity(&self) -> Result<([u8; 16], [u8; 16])> {
        let metadata = self.metadata()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let mut volume = [0; 16];
            let mut file = [0; 16];
            volume[..8].copy_from_slice(&metadata.dev().to_be_bytes());
            file[..8].copy_from_slice(&metadata.ino().to_be_bytes());
            Ok((volume, file))
        }
        #[cfg(windows)]
        {
            let _ = metadata;
            let revision = crate::observe_file_revision(&self.file)
                .map_err(|e| io_error("inspect retained database identity", &self.path, e))?;
            Ok((revision.volume, revision.file))
        }
    }
}
