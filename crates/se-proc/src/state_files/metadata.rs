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
        let Some(file) = files.directory.pin_metadata(path, &files.root)? else {
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
        #[cfg(windows)]
        let started = std::time::Instant::now();
        #[cfg(windows)]
        self.files.check(&self.path)?;
        #[cfg(windows)]
        let root_before_us = started.elapsed().as_micros();
        // Reuse one protected Windows handle for metadata and file identity.
        #[cfg(windows)]
        let other = self
            .files
            .directory
            .pin_metadata(&self.path, &self.files.root)?
            .ok_or_else(|| {
                failure(
                    StateFileErrorCode::SourceChanged,
                    "database name disappeared",
                    &self.path,
                )
            })?;
        #[cfg(windows)]
        let opened_us = started.elapsed().as_micros();
        #[cfg(windows)]
        let named = other
            .metadata()
            .map_err(|e| io_error("inspect named database metadata", &self.path, e))?;
        #[cfg(windows)]
        let named_us = started.elapsed().as_micros();
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
        #[cfg(windows)]
        let same = {
            let a = crate::observe_file_revision(&self.file)
                .map_err(|e| io_error("inspect retained database identity", &self.path, e))?;
            let b = crate::observe_file_revision(&other)
                .map_err(|e| io_error("inspect named database identity", &self.path, e))?;
            a.volume == b.volume && a.file == b.file
        };
        #[cfg(windows)]
        let identity_us = started.elapsed().as_micros();
        #[cfg(windows)]
        self.files.check(&self.path)?;
        #[cfg(windows)]
        let root_after_us = started.elapsed().as_micros();
        #[cfg(windows)]
        drop(other);
        #[cfg(windows)]
        eprintln!(
            "native-pin-timing root_before_us={} open_us={} metadata_us={} identity_us={} root_after_us={} close_us={}",
            root_before_us,
            opened_us - root_before_us,
            named_us - opened_us,
            identity_us - named_us,
            root_after_us - identity_us,
            started.elapsed().as_micros() - root_after_us,
        );
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
