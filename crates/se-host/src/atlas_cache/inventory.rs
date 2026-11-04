//! Finite activation inventory. The exclusive home lease prevents cooperating
//! writers changing other roots while this adapter owns its cached total.
use super::*;
pub(super) fn measure(home: &NativeStateFiles, wanted: &Path) -> AtlasResult<(u64, u64)> {
    let mut entries = 0;
    let mut root = 0;
    let total = walk(home, 0, wanted, &mut root, &mut entries)?;
    Ok((total, root))
}
pub(super) fn root(files: &NativeStateFiles) -> AtlasResult<u64> {
    let mut entries = 0;
    let mut bytes = 0;
    walk(files, 2, files.root(), &mut bytes, &mut entries)
}
fn walk(
    files: &NativeStateFiles,
    depth: u8,
    wanted: &Path,
    root: &mut u64,
    entries: &mut u32,
) -> AtlasResult<u64> {
    let mut total = 0u64;
    let mut epoch_count = 0;
    // A missing sentinel is a native check of the original retained directory;
    // it is never created. Entry reads repeat that custody check themselves.
    files
        .readback(&files.root().join(".atlas-inventory-check"))
        .map_err(fail)?;
    for entry in std::fs::read_dir(files.root()).map_err(fail)? {
        let entry = entry.map_err(fail)?;
        *entries += 1;
        if *entries > 32768 {
            return Err(busy("Atlas activation inventory entries", 1, 0));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| fail("non-UTF-8 Atlas cache name preserved"))?;
        let kind = entry.file_type().map_err(fail)?;
        let path = entry.path();
        let size = if kind.is_dir() {
            if depth == 3 {
                epoch_count += 1;
                if epoch_count > 3 {
                    return Err(busy("Atlas current/retired/staging epoch slots", 1, 0));
                }
            }
            let allowed = match depth {
                0 => se_types::ProjectId::from_legacy(name.clone()).is_ok(),
                1 => name.parse::<se_types::AtlasRootId>().is_ok(),
                2 => name == "epochs",
                3 => name.parse::<CacheEpoch>().is_ok(),
                _ => false,
            };
            if !allowed {
                return Err(fail(
                    "unknown Atlas cache directory preserved; inspect before growth",
                ));
            }
            let child = NativeStateFiles::open(&path).map_err(fail)?;
            walk(&child, depth + 1, wanted, root, entries)?
        } else {
            let allowed = name.starts_with(".se-stage-")
                || match depth {
                    0 => name == "writer.lock",
                    2 => name == "current.json",
                    4 => matches!(name.as_str(), "atlas.db" | "atlas.db-wal" | "atlas.db-shm"),
                    _ => false,
                };
            if !allowed || !kind.is_file() {
                return Err(fail(
                    "unknown or linked Atlas cache entry preserved; inspect before growth",
                ));
            }
            files
                .readback(&path)
                .map_err(fail)?
                .ok_or_else(|| fail("Atlas inventory file disappeared"))?
                .metadata()
                .map_err(fail)?
                .len()
        };
        total = total
            .checked_add(size)
            .ok_or_else(|| fail("Atlas inventory byte overflow"))?;
    }
    files
        .readback(&files.root().join(".atlas-inventory-check"))
        .map_err(fail)?;
    if files.root() == wanted {
        *root = total
    }
    Ok(total)
}
