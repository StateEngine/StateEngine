//! A newly created executable is journaled before its first byte is copied.
//! The guardian retires it after native exit; later commands recover crashes.
use super::*;
use sha2::Digest;
use std::os::windows::fs::OpenOptionsExt;

pub(super) struct CarrierCopy {
    pub file: File,
    pub path: PathBuf,
    pub journal: PathBuf,
    pub journal_file: File,
    pub directory: Option<PathBuf>,
}
impl CarrierCopy {
    pub fn create(
        files: &NativeStateFiles,
        staging_files: &NativeStateFiles,
        source: &mut File,
        expected: [u8; 32],
        directory: Option<staging::DirectoryCustody>,
    ) -> Result<Self> {
        let staged = staging_files
            .create_staging(staging_files.root())
            .map_err(custody)?;
        let path = staged.path.with_extension("exe");
        let identity = native::file_id(&staged.file)?;
        // Publication opens its own writer: close the creation writer first.
        drop(staged.file);
        staging_files
            .publish_no_replace(&staged.path, &path)
            .map_err(custody)?;
        let mut file = File::options()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .map_err(|e| error("open new carrier copy", e))?;
        let checked = staging_files
            .readback(&path)
            .map_err(custody)?
            .ok_or_else(|| refuse("admit new carrier copy", "created name disappeared"))?;
        if native::file_id(&file)? != identity || native::file_id(&checked)? != identity {
            return Err(refuse(
                "admit new carrier copy",
                "created name was replaced",
            ));
        }
        if directory.is_some() {
            staging::verify_high(&file, false)?;
        }
        drop(checked);
        let debt = UninstallHelperCleanup::created(
            files,
            path.clone(),
            &file,
            expected,
            directory.clone(),
        )?;
        let bytes = debt.encode()?;
        let journal = files.root().join(UninstallHelperCleanup::RECORD_NAME);
        let record = files.create_staging(files.root()).map_err(custody)?;
        let record_path = record.path;
        let mut record_file = record.file;
        let journal_identity = native::file_id(&record_file)?;
        record_file
            .write_all(&bytes)
            .and_then(|()| record_file.sync_all())
            .map_err(|e| error("write carrier cleanup custody", e))?;
        drop(record_file);
        files
            .publish_no_replace(&record_path, &journal)
            .map_err(custody)?;
        // From this point every failure retains an independently readable,
        // exact-object recovery record, including an interrupted partial copy.
        let pending_copy = path.clone();
        let pending_journal = journal.clone();
        let result = (|| {
            source
                .rewind()
                .map_err(|e| error("rewind original carrier image", e))?;
            io::copy(source, &mut file)
                .and_then(|_| file.sync_all())
                .map_err(|e| error("copy private carrier image", e))?;
            if native::digest(&mut file)? != expected {
                return Err(refuse("admit private carrier copy", "copied image differs"));
            }
            // A writable open must not survive the image-section creation.
            drop(file);
            let mut file = native::open_image(&path, false)?;
            let mut journal_file = native::open_image(&journal, false)?;
            if native::file_id(&file)? != identity
                || native::digest(&mut file)? != expected
                || native::file_id(&journal_file)? != journal_identity
                || native::digest(&mut journal_file)?
                    != <[u8; 32]>::from(sha2::Sha256::digest(&bytes))
            {
                return Err(refuse(
                    "seal private carrier custody",
                    "created object identity or bytes changed",
                ));
            }
            Ok(Self {
                file,
                path,
                journal,
                journal_file,
                directory: directory.map(|d| d.path),
            })
        })();
        result.map_err(|mut cause: UninstallNativeError| {
            cause.pending_paths.extend([pending_copy, pending_journal]);
            cause
        })
    }
}
