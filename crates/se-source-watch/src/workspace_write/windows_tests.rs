use super::*;
use crate::source_root::NativeSourceRoot;
use std::path::PathBuf;

type Check = Result<(), Box<dyn std::error::Error>>;

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn scratch(label: &str) -> Result<Scratch, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "se-workspace-write-win-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(Scratch(dir))
}

#[test]
fn write_relative_creates_replaces_and_refuses_concurrent_create() -> Check {
    let dir = scratch("nt-rename")?;
    let root = NativeSourceRoot::open(&dir.0)?;

    // Create new file under nested directory via handle-relative NtSetInformationFile.
    root.write_relative("nested/note.txt", b"v1")?;
    assert_eq!(std::fs::read(dir.0.join("nested").join("note.txt"))?, b"v1");

    // Replace existing file via ReplaceFileW (retaining & verifying displaced backup).
    root.write_relative("nested/note.txt", b"v2-updated")?;
    assert_eq!(
        std::fs::read(dir.0.join("nested").join("note.txt"))?,
        b"v2-updated"
    );

    // Non-replacing rename must refuse overwriting an existing target.
    let mut stage_units = utf16_component("stage.tmp")?;
    let leaf_units = utf16_component("existing.txt")?;
    std::fs::write(dir.0.join("existing.txt"), b"other-writer")?;
    let mut stage = nt_open_relative(
        &root.directory,
        &mut stage_units,
        DELETE | GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
        0,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    )?;
    stage.write_all(b"stale-create")?;
    let err = rename_at(&stage, &root.directory, &leaf_units, false)
        .err()
        .ok_or("expected non-replacing rename to fail on existing target")?;
    assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
    dispose_stage(&stage);
    drop(stage);
    assert_eq!(std::fs::read(dir.0.join("existing.txt"))?, b"other-writer");

    // An open concurrent writer holding write access must block replacement
    // cleanly instead of being silently clobbered.
    let writer = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.0.join("existing.txt"))?;
    let conflict = root
        .write_relative("existing.txt", b"clobber")
        .err()
        .ok_or("expected open writer to block replacement")?;
    assert!(matches!(
        conflict,
        WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::Io(_))
    ));
    drop(writer);
    assert_eq!(std::fs::read(dir.0.join("existing.txt"))?, b"other-writer");
    Ok(())
}
