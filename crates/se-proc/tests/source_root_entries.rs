#[path = "../../test-support/directory_owner.rs"]
mod cleanup_directory;
use se_proc::{NativeSourceKind, NativeSourceRoot};
use std::{
    collections::BTreeMap,
    fs,
    time::{SystemTime, UNIX_EPOCH},
};
type Check = Result<(), Box<dyn std::error::Error>>;
#[test]
fn retained_directory_streams_restart_and_reject_replaced_names() -> Check {
    let base = std::env::temp_dir().join(format!(
        "atlas-source-entries-{}-{}",
        std::process::id(),
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    fs::create_dir(&base)?;
    let _root_owner = cleanup_directory::PrivateDirectory::for_case(base.clone());
    let root = base.join("root");
    fs::create_dir_all(root.join("nested"))?;
    fs::write(root.join("file.rs"), "fn example() {}")?;
    fs::write(root.join("nested/retained.rs"), "retained")?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(base.join("outside"), root.join("link"))?;
    let source = NativeSourceRoot::open(&root)?;
    let mut previous = None;
    for _ in 0..2 {
        let mut cursor = source.open_directory("")?.ok_or("root absent")?;
        let mut entries = BTreeMap::new();
        while let Some(entry) = cursor.next_entry()? {
            entries.insert(entry.name, entry.kind);
            assert!(entries.len() < 16, "finite private fixture");
        }
        assert_eq!(
            entries.get(std::ffi::OsStr::new("file.rs")),
            Some(&NativeSourceKind::File)
        );
        assert_eq!(
            entries.get(std::ffi::OsStr::new("nested")),
            Some(&NativeSourceKind::Directory)
        );
        #[cfg(unix)]
        assert_eq!(
            entries.get(std::ffi::OsStr::new("link")),
            Some(&NativeSourceKind::Link)
        );
        if let Some(expected) = previous {
            assert_eq!(entries, expected)
        }
        previous = Some(entries);
    }
    fs::create_dir(root.join("batch"))?;
    for i in 0..257 {
        fs::write(root.join("batch").join(format!("{i}.rs")), b"bounded")?;
    }
    let mut batched = source.open_directory("batch")?.ok_or("batch absent")?;
    let mut names = std::collections::BTreeSet::new();
    loop {
        let entries = batched.next_batch()?;
        assert!(entries.len() <= 128);
        if entries.is_empty() {
            break;
        }
        for entry in entries {
            assert_eq!(entry.kind, NativeSourceKind::File);
            assert!(names.insert(entry.name), "duplicate directory entry");
        }
    }
    assert_eq!(names.len(), 257, "batch boundary lost entries");
    drop(batched);
    let mut cursor = source.open_directory("nested")?.ok_or("nested absent")?;
    fs::rename(root.join("nested"), base.join("moved"))?;
    fs::create_dir(root.join("nested"))?;
    assert!(!cursor.validate_name()?);
    assert!(cursor.next_entry().is_err());
    assert!(cursor.next_batch().is_err());
    assert_eq!(fs::read(base.join("moved/retained.rs"))?, b"retained");
    drop(cursor);
    drop(source);

    _root_owner.finish(Ok(()))
}
