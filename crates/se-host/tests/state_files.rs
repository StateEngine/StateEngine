//! Exercise the shared production store port with both caller policies and
//! independent native readback; the existing CLI/host consumers cover routing.
use se_host::state_files::{FilePolicy, Files};
use se_proc::NativeStateFiles;
use se_store::{StateFiles, StoreErrorCode};
use se_types::{Read, Retry};
use sha2::{Digest, Sha256};
use std::{fs, io::Write, path::PathBuf};
type Check = Result<(), Box<dyn std::error::Error>>;

struct Home(PathBuf);
impl Home {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        se_proc::initialize_file_creation_owner()?;
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "se-shared-files-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        drop(NativeStateFiles::create(&path)?);
        Ok(Self(path))
    }
    fn files(&self, policy: FilePolicy) -> Result<Files, Box<dyn std::error::Error>> {
        Ok(Files::open_with_policy(&self.0, policy)?)
    }
    fn outside(&self, name: &str) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        use std::io::Read as _;
        let reader = NativeStateFiles::open(&self.0)?;
        let Some(mut file) = reader.readback(&self.0.join(name))? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(Some(bytes))
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_dir_all(&self.0) {
            eprintln!("owned shared StateFiles fixture cleanup: {error}");
        }
    }
}
const POLICIES: [FilePolicy; 2] = [FilePolicy::Direct, FilePolicy::Host];

#[test]
fn directory_allowlists_and_recovery_advice_are_caller_policy() -> Check {
    for policy in POLICIES {
        let home = Home::new()?;
        let files = home.files(policy)?;
        for name in ["backups", "staging"] {
            files.prepare_directory(&home.0.join(name))?;
            assert!(fs::metadata(home.0.join(name))?.is_dir());
        }
        let transcripts = home.0.join("transcripts");
        match policy {
            FilePolicy::Host => files.prepare_directory(&transcripts)?,
            FilePolicy::Direct => {
                let error = files
                    .prepare_directory(&transcripts)
                    .err()
                    .ok_or("direct transcripts accepted")?;
                assert_eq!(error.code, StoreErrorCode::LocationUnsafe);
                assert!(error.remedy.text.contains("explicit init"));
                assert!(!transcripts.exists());
            }
        }
        let other = home.0.join("other");
        let error = files
            .prepare_directory(&other)
            .err()
            .ok_or("unexpected directory prepared")?;
        assert_eq!(error.code, StoreErrorCode::LocationUnsafe);
        assert_eq!(error.retry, Retry::AfterReread);
        if policy == FilePolicy::Host {
            assert!(error.remedy.text.contains("exact native custody"));
        }
        assert!(!other.exists());
    }
    Ok(())
}

#[test]
fn inventory_is_complete_or_refuses_with_the_callers_public_code() -> Check {
    for policy in POLICIES {
        let home = Home::new()?;
        let files = home.files(policy)?;
        assert!(files.list_owned(&home.0, 1)?.is_empty());
        let error = files
            .list_owned(&home.0, 0)
            .err()
            .ok_or("zero inventory bound accepted")?;
        assert_eq!(
            error.code,
            match policy {
                FilePolicy::Direct => StoreErrorCode::ReadBudgetTooSmall,
                FilePolicy::Host => StoreErrorCode::BackupFailed,
            }
        );
        files.prepare_directory(&home.0.join("backups"))?;
        for name in ["backups/a", "backups/b"] {
            files.replace_owned(&home.0.join(name), None, name.as_bytes())?;
        }
        let directory = home.0.join("backups");
        let error = files
            .list_owned(&directory, 1)
            .err()
            .ok_or("inventory truncated")?;
        assert_eq!(
            error.code,
            match policy {
                FilePolicy::Direct => StoreErrorCode::ReadIncomplete,
                FilePolicy::Host => StoreErrorCode::BackupFailed,
            }
        );
        let mut paths = files.list_owned(&directory, 2)?;
        paths.sort();
        assert_eq!(paths, vec![directory.join("a"), directory.join("b")]);
        assert_eq!(home.outside("backups/a")?, Some(b"backups/a".to_vec()));
        assert_eq!(home.outside("backups/b")?, Some(b"backups/b".to_vec()));
    }
    Ok(())
}

#[test]
fn replacement_and_retirement_preserve_expected_digest_and_presence() -> Check {
    for policy in POLICIES {
        let home = Home::new()?;
        let files = home.files(policy)?;
        let path = home.0.join("manifest");
        assert!(matches!(files.readback(&path)?, Read::Absent { .. }));
        files.replace_owned(&path, None, b"first")?;
        assert_eq!(home.outside("manifest")?, Some(b"first".to_vec()));
        for expected in [None, Some([0; 32])] {
            let error = files
                .replace_owned(&path, expected, b"unexpected")
                .err()
                .ok_or("wrong expectation replaced bytes")?;
            assert_eq!(error.code, StoreErrorCode::SourceChanged);
            assert_eq!(home.outside("manifest")?, Some(b"first".to_vec()));
        }
        let error = files
            .remove_owned(&path, [0; 32])
            .err()
            .ok_or("wrong digest removed bytes")?;
        assert_eq!(error.code, StoreErrorCode::SourceChanged);
        files.replace_owned(&path, Some(Sha256::digest(b"first").into()), b"second")?;
        assert_eq!(home.outside("manifest")?, Some(b"second".to_vec()));
        files.remove_owned(&path, Sha256::digest(b"second").into())?;
        assert!(home.outside("manifest")?.is_none());
        assert_eq!(
            files
                .replace_owned(&path, Some([0; 32]), b"unexpected")
                .err()
                .ok_or("absent expected file created")?
                .code,
            StoreErrorCode::SourceChanged
        );
        assert!(home.outside("manifest")?.is_none());
    }
    Ok(())
}

#[test]
fn publication_never_replaces_and_staging_retirement_is_digest_checked() -> Check {
    for policy in POLICIES {
        let home = Home::new()?;
        let files = home.files(policy)?;
        let path = home.0.join("manifest");
        files.replace_owned(&path, None, b"winner")?;
        let mut stage = files.create_staging(&home.0)?;
        stage.file.write_all(b"loser")?;
        stage.file.sync_all()?;
        drop(stage.file);
        assert_eq!(
            files
                .publish_no_replace(&stage.path, &path)
                .err()
                .ok_or("publication replaced winner")?
                .code,
            StoreErrorCode::AlreadyExists
        );
        assert_eq!(home.outside("manifest")?, Some(b"winner".to_vec()));
        assert_eq!(
            files
                .retire_staging(&stage.path, [0; 32])
                .err()
                .ok_or("wrong staging digest removed bytes")?
                .code,
            StoreErrorCode::SourceChanged
        );
        assert!(stage.path.exists());
        files.retire_staging(&stage.path, Sha256::digest(b"loser").into())?;
        assert!(!stage.path.exists());
        assert_eq!(
            files
                .retire_staging(&path, Sha256::digest(b"winner").into())
                .err()
                .ok_or("ordinary file retired as staging")?
                .code,
            StoreErrorCode::LocationUnsafe
        );
        assert_eq!(home.outside("manifest")?, Some(b"winner".to_vec()));
    }
    Ok(())
}

#[test]
fn effects_outside_the_retained_root_refuse_without_mutation() -> Check {
    for policy in POLICIES {
        let home = Home::new()?;
        let files = home.files(policy)?;
        let other = Home::new()?;
        let path = other.0.join("manifest");
        assert_eq!(
            files
                .replace_owned(&path, None, b"unexpected")
                .err()
                .ok_or("foreign root accepted")?
                .code,
            StoreErrorCode::LocationUnsafe
        );
        assert!(other.outside("manifest")?.is_none());
        assert_eq!(
            files
                .list_owned(&other.0, 1)
                .err()
                .ok_or("foreign inventory accepted")?
                .code,
            StoreErrorCode::LocationUnsafe
        );
    }
    Ok(())
}

#[test]
fn unsafe_readback_and_inventory_do_not_become_absence_or_partial_success() -> Check {
    for policy in POLICIES {
        let home = Home::new()?;
        let files = home.files(policy)?;
        files.prepare_directory(&home.0.join("backups"))?;
        let path = home.0.join("backups/manifest");
        files.replace_owned(&path, None, b"preserved")?;
        let alias = home.0.join("backups/alias");
        fs::hard_link(&path, &alias)?;
        assert_eq!(
            files
                .readback(&path)
                .err()
                .ok_or("multiply linked file read")?
                .code,
            StoreErrorCode::LocationUnsafe
        );
        assert_eq!(
            files
                .list_owned(&home.0.join("backups"), 10)
                .err()
                .ok_or("unsafe inventory partially accepted")?
                .code,
            StoreErrorCode::LocationUnsafe
        );
        assert_eq!(fs::read(&path)?, b"preserved");
        assert_eq!(fs::read(&alias)?, b"preserved");
    }
    Ok(())
}
