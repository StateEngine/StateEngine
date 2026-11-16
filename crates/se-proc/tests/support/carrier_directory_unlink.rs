use super::*;
use crate::windows_policy_fixture::{Check, Home};

#[path = "carrier_completion.rs"]
mod completion;

fn held(file: File, path: &Path, kind: &str) -> Check<super::super::entry::Held> {
    let directory = kind == "directory";
    let identity = super::super::entry_effects::identity(&file, directory)?;
    let mut file = file;
    let sha256 = if directory {
        None
    } else {
        Some(se_types::hex_lower(&native::digest(&mut file)?))
    };
    let object = serde_json::from_value(serde_json::json!({
        "handle":file.as_raw_handle() as usize as u64, "path":path, "kind":kind,
        "identity":identity, "sha256":sha256,
    }))?;
    Ok(super::super::entry::Held { object, file })
}

fn inventory(
    home: &Path,
    path: &Path,
    original: &File,
    label: &str,
) -> Check<Vec<super::super::entry::Held>> {
    // The production effect removes image/record before directories. These two
    // synthetic regular files let the judge reach that same path without a
    // second implementation or a shell/compiler extracting obsolete source.
    let mut objects = Vec::new();
    for kind in ["image", "record"] {
        let file = home.join(format!("{label}-{kind}"));
        std::fs::write(&file, format!("synthetic {kind}"))?;
        objects.push(held(native::open_image(&file, false)?, &file, kind)?);
    }
    objects.push(held(original.try_clone()?, path, "directory")?);
    Ok(objects)
}

fn directory_effect(home: &Path, path: &Path, original: &File, label: &str) -> Check<Result<()>> {
    let mut objects = inventory(home, path, original, label)?;
    Ok(super::super::entry_effects::remove(&mut objects))
}

/// Protects: J5 — the Rust carrier effect removes original empty directories,
/// preserves nonempty contents and refuses names replaced after pinning.
#[test]
fn readable_carrier_removes_only_original_empty_directories() -> Check {
    let home = Home::new()?;
    let empty = home.0.join("empty");
    let occupied = home.0.join("occupied");
    let replaced = home.0.join("replaced");
    let moved = home.0.join("original");
    let mut pins = Vec::new();
    for path in [&empty, &occupied, &replaced] {
        std::fs::create_dir(path)?;
        pins.push(
            crate::state_files::windows::effects::uninstall_directory(path)?
                .ok_or("original directory absent")?,
        );
    }
    std::fs::write(occupied.join("foreign.txt"), b"preserved foreign work")?;
    std::fs::rename(&replaced, &moved)?;
    std::fs::create_dir(&replaced)?;
    std::fs::write(replaced.join("foreign.txt"), b"preserved replacement")?;

    directory_effect(&home.0, &empty, &pins[0], "empty")??;
    directory_effect(&home.0, &occupied, &pins[1], "occupied")??;
    let Err(refusal) = directory_effect(&home.0, &replaced, &pins[2], "replaced")? else {
        return Err("replacement directory was adopted".into());
    };
    assert_eq!(refusal.operation, "unlink carrier directory");
    assert!(refusal.source.to_string().contains("replacement preserved"));

    // Every original pin remains open during this independent readback.
    assert_eq!(
        std::fs::symlink_metadata(&empty).err().map(|e| e.kind()),
        Some(io::ErrorKind::NotFound)
    );
    assert!(moved.is_dir());
    assert_eq!(
        std::fs::read(occupied.join("foreign.txt"))?,
        b"preserved foreign work"
    );
    assert_eq!(
        std::fs::read(replaced.join("foreign.txt"))?,
        b"preserved replacement"
    );
    Ok(())
}

/// Protects: J5 — preserve a nonempty retained home despite the live root pin denying delete sharing.
#[test]
fn retained_nonempty_root_does_not_require_delete_sharing() -> Check {
    let home = Home::new()?;
    let files = NativeStateFiles::open(&home.0)?;
    let retained = home.0.join("retained-history.db");
    std::fs::write(&retained, b"retained history")?;
    assert_eq!(
        crate::remove_empty_directory(&home.0)?,
        crate::DirectoryRemoval::NotEmpty
    );
    assert_eq!(std::fs::read(&retained)?, b"retained history");
    // The same reader must still remove an actually empty ordinary directory.
    let empty = home.0.join("empty-child");
    std::fs::create_dir(&empty)?;
    assert_eq!(
        crate::remove_empty_directory(&empty)?,
        crate::DirectoryRemoval::Removed
    );
    assert_eq!(
        std::fs::symlink_metadata(&empty)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::NotFound)
    );
    drop(files);
    Ok(())
}
