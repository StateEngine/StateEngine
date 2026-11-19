//! Metadata custody must not close an ordinary descriptor on a live SQLite inode.
use super::*;
use std::fs::Metadata;

pub struct NativeMetadataPin {
    files: NativeStateFiles,
    path: PathBuf,
    #[cfg(windows)]
    direct_metadata: bool,
    #[cfg(not(target_os = "macos"))]
    file: File,
    #[cfg(target_os = "macos")]
    original: Metadata,
}
impl NativeMetadataPin {
    /// Whether held ancestry and this name are qualified for direct NTFS metadata.
    #[cfg(windows)]
    pub fn is_ordinary_local(&self) -> bool {
        self.direct_metadata
    }
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
        let files = NativeStateFiles::open(&files.root)?;
        #[cfg(windows)]
        let direct_metadata = files.directory.admit_metadata(path, &files.root)?;
        let pin = Self {
            files,
            path: path.into(),
            #[cfg(windows)]
            direct_metadata,
            #[cfg(not(target_os = "macos"))]
            file,
            #[cfg(target_os = "macos")]
            original,
        };
        pin.metadata()?;
        Ok(Some(pin))
    }
    pub fn metadata(&self) -> Result<Metadata> {
        #[cfg(windows)]
        let (named, same) = {
            let other = if self.direct_metadata {
                self.files
                    .directory
                    .read_admitted_metadata(&self.path, &self.files.root)?
            } else {
                self.files.check(&self.path)?;
                self.files
                    .directory
                    .readback(&self.path, &self.files.root)?
            };
            // One protected handle supplies both facts. A second named open
            // repeats protection checks and can observe a different file.
            let other = other.ok_or_else(|| {
                failure(
                    StateFileErrorCode::SourceChanged,
                    "database metadata name disappeared",
                    &self.path,
                )
            })?;
            let named = other
                .metadata()
                .map_err(|e| io_error("inspect native metadata", &self.path, e))?;
            let a = crate::observe_file_revision(&self.file)
                .map_err(|e| io_error("inspect retained database identity", &self.path, e))?;
            let b = crate::observe_file_revision(&other)
                .map_err(|e| io_error("inspect named database identity", &self.path, e))?;
            if self.direct_metadata {
                self.files.directory.check_metadata_name(&self.files.root)?;
            } else {
                self.files.check(&self.path)?;
            }
            (named, a.volume == b.volume && a.file == b.file)
        };
        #[cfg(unix)]
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
