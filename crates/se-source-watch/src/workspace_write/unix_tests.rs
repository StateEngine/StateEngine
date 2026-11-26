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
        "se-workspace-write-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir)?;
    Ok(Scratch(dir))
}

#[test]
fn exclusive_publish_refuses_concurrently_created_target() -> Check {
    let dir = scratch("exclusive")?;
    let root = File::open(&dir.0)?;
    std::fs::write(dir.0.join("stage"), b"stale")?;
    std::fs::write(dir.0.join("leaf"), b"concurrent-writer")?;
    let err = publish_exclusive(&root, &cstr("stage")?, &cstr("leaf")?)
        .err()
        .ok_or("expected exclusive publish to fail")?;
    assert!(matches!(
        err,
        WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::Io(ref e))
            if e.kind() == io::ErrorKind::AlreadyExists
    ));
    assert_eq!(std::fs::read(dir.0.join("leaf"))?, b"concurrent-writer");
    Ok(())
}

#[test]
fn moved_child_directory_fails_parent_chain_custody() -> Check {
    let outer = scratch("moved-parent")?;
    let ws = outer.0.join("ws");
    std::fs::create_dir_all(ws.join("sub"))?;
    let root = File::open(&ws)?;
    let root_mount = root_mount_identity(&root)?;
    let (sub_dir, sub_id) = open_or_create_dir(&root, "sub", root_mount)?;
    let chain = vec![("sub", sub_dir, sub_id)];

    // Move `ws/sub` outside `ws` while its fd is held.
    std::fs::rename(ws.join("sub"), outer.0.join("escaped"))?;
    let err = verify_parent_chain(&root, &chain, root_mount)
        .err()
        .ok_or("expected parent custody refusal after move")?;
    assert!(matches!(
        err,
        WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::InvalidTarget(_))
    ));
    Ok(())
}

#[test]
fn target_baseline_detects_concurrent_modification() -> Check {
    let dir = scratch("baseline")?;
    let root = File::open(&dir.0)?;
    let root_mount = root_mount_identity(&root)?;
    let leaf = cstr("note.txt")?;
    std::fs::write(dir.0.join("note.txt"), b"v1")?;
    let baseline = inspect_target_leaf(&root, &leaf, root_mount, None)?;
    assert!(baseline.is_some());

    std::fs::write(dir.0.join("note.txt"), b"v2-longer")?;
    let err = verify_target_unchanged(&root, &leaf, root_mount, None, baseline)
        .err()
        .ok_or("expected concurrent modification refusal")?;
    assert!(matches!(
        err,
        WorkspaceWriteError::BeforePublish(WorkspaceWriteRefusal::InvalidTarget(_))
    ));
    Ok(())
}

#[test]
fn publish_replace_rolls_back_and_preserves_concurrent_editor_save() -> Check {
    let dir = scratch("exchange-rollback")?;
    let root = File::open(&dir.0)?;
    let root_mount = root_mount_identity(&root)?;
    let leaf = cstr("note.txt")?;
    let stage = cstr(".se-write-stage")?;
    std::fs::write(dir.0.join("note.txt"), b"v1")?;
    let expected =
        inspect_target_leaf(&root, &leaf, root_mount, None)?.ok_or("missing initial baseline")?;
    let stage_baseline = stage_file(&root, &stage, b"agent-write", Some(expected))?;

    // Simulate a concurrent editor saving a new version right before exchange.
    std::fs::write(dir.0.join("note.txt"), b"concurrent-editor-save")?;

    let err = publish_replace(&ReplaceCtx {
        root: &root,
        chain: &[],
        parent: &root,
        stage: &stage,
        leaf: &leaf,
        stage_baseline,
        expected,
        root_mount,
        dot_git: None,
        root_check: &|| Ok(()),
    })
    .err()
    .ok_or("expected exchange rollback on concurrent edit")?;
    assert!(matches!(err, WorkspaceWriteError::Restored(_)));
    assert_eq!(
        std::fs::read(dir.0.join("note.txt"))?,
        b"concurrent-editor-save"
    );
    assert!(!dir.0.join(".se-write-stage").exists());
    Ok(())
}

#[test]
fn write_relative_creates_and_replaces_existing_file() -> Check {
    let dir = scratch("create-replace")?;
    let root = NativeSourceRoot::open(&dir.0)?;
    root.write_relative("sub/note.txt", b"v1")?;
    assert_eq!(std::fs::read(dir.0.join("sub").join("note.txt"))?, b"v1");

    // Normal replacement must succeed even though renameat2(RENAME_EXCHANGE)
    // updates ctime on the displaced original.
    root.write_relative("sub/note.txt", b"v2-replaced")?;
    assert_eq!(
        std::fs::read(dir.0.join("sub").join("note.txt"))?,
        b"v2-replaced"
    );
    Ok(())
}

#[test]
fn publish_replace_rolls_back_when_parent_displaced() -> Check {
    let outer = scratch("exchange-displaced")?;
    let ws = outer.0.join("ws");
    std::fs::create_dir_all(ws.join("sub"))?;
    let root = File::open(&ws)?;
    let root_mount = root_mount_identity(&root)?;
    let (sub_dir, sub_id) = open_or_create_dir(&root, "sub", root_mount)?;
    let leaf = cstr("note.txt")?;
    let stage = cstr(".se-write-stage")?;
    std::fs::write(ws.join("sub").join("note.txt"), b"original")?;
    let expected = inspect_target_leaf(&sub_dir, &leaf, root_mount, None)?
        .ok_or("missing initial baseline")?;
    let stage_baseline = stage_file(&sub_dir, &stage, b"agent-write", Some(expected))?;

    // Displace `ws/sub` outside `ws` right before exchange.
    std::fs::rename(ws.join("sub"), outer.0.join("escaped"))?;
    let chain = vec![("sub", sub_dir, sub_id)];
    let parent = &chain[0].1;

    let err = publish_replace(&ReplaceCtx {
        root: &root,
        chain: &chain,
        parent,
        stage: &stage,
        leaf: &leaf,
        stage_baseline,
        expected,
        root_mount,
        dot_git: None,
        root_check: &|| Ok(()),
    })
    .err()
    .ok_or("expected rollback when parent displaced")?;
    assert!(matches!(err, WorkspaceWriteError::Restored(_)));
    assert_eq!(
        std::fs::read(outer.0.join("escaped").join("note.txt"))?,
        b"original"
    );
    assert!(!outer.0.join("escaped").join(".se-write-stage").exists());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn same_device_different_mount_id_or_mount_root_is_refused() {
    let root_mount = MountIdentity {
        dev: 42,
        mnt_id: Some(100),
    };
    let same_dev_other_mnt = EntryMeta {
        dev: 42,
        ino: 1,
        mode: libc::S_IFDIR | 0o755,
        size: 0,
        mtime_sec: 0,
        mtime_nsec: 0,
        mnt_id: Some(101),
        is_mount_root: false,
    };
    assert!(matches!(
        verify_same_mount(same_dev_other_mnt, root_mount, "path"),
        Err(WorkspaceWriteError::BeforePublish(
            WorkspaceWriteRefusal::InvalidTarget(_)
        ))
    ));
    let mount_root = EntryMeta {
        mnt_id: Some(100),
        is_mount_root: true,
        ..same_dev_other_mnt
    };
    assert!(matches!(
        verify_same_mount(mount_root, root_mount, "path"),
        Err(WorkspaceWriteError::BeforePublish(
            WorkspaceWriteRefusal::InvalidTarget(_)
        ))
    ));
}
