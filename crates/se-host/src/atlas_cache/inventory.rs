//! Per-root disk inventory. Idle projects are never walked while another root
//! grows; project count does not impose a whole-home ceiling or scan.
use super::*;
const MAX_RETAINED_FILES: usize = 32;

pub(super) struct Inventory {
    directories: Vec<(
        NativeStateFiles,
        Vec<(std::ffi::OsString, std::fs::FileType)>,
    )>,
    files: Vec<InventoryFile>,
    complete: bool,
}
struct InventoryFile {
    path: PathBuf,
    pin: se_proc::NativeMetadataPin,
    #[cfg(windows)]
    guard: Option<File>,
}
impl InventoryFile {
    fn new(path: PathBuf, pin: se_proc::NativeMetadataPin, retain: bool) -> AtlasResult<Self> {
        #[cfg(windows)]
        let guard = if retain {
            pin.hold_no_delete().map_err(fail)?
        } else {
            None
        };
        #[cfg(not(windows))]
        let _ = retain;
        Ok(Self {
            path,
            pin,
            #[cfg(windows)]
            guard,
        })
    }
    fn metadata(&self) -> Option<std::fs::Metadata> {
        #[cfg(windows)]
        if let Some(guard) = &self.guard {
            return guard.metadata().ok();
        }
        self.pin.metadata().ok()
    }
}

impl Inventory {
    pub(super) fn file_size(&self, path: &Path) -> Option<u64> {
        self.files
            .iter()
            .find(|item| item.path == path)
            .and_then(InventoryFile::metadata)
            .map(|metadata| metadata.len())
    }

    pub(super) fn measure(&self) -> AtlasResult<Option<u64>> {
        if !self.complete {
            return Ok(None);
        }
        for (files, previous) in &self.directories {
            if files
                .readback(&files.root().join(".atlas-inventory-check"))
                .is_err()
            {
                return Ok(None);
            }
            if !entries_match(files.root(), previous) {
                return Ok(None);
            }
        }
        let mut bytes = 0u64;
        for item in &self.files {
            let metadata = match item.metadata() {
                Some(value) => value,
                None => return Ok(None),
            };
            bytes = bytes
                .checked_add(metadata.len())
                .ok_or_else(|| fail("Atlas inventory byte overflow"))?;
        }
        for (files, previous) in &self.directories {
            if !entries_match(files.root(), previous)
                || files
                    .readback(&files.root().join(".atlas-inventory-check"))
                    .is_err()
            {
                return Ok(None);
            }
        }
        Ok(Some(bytes))
    }
}

fn entries_match(path: &Path, previous: &[(std::ffi::OsString, std::fs::FileType)]) -> bool {
    let Ok(entries) = std::fs::read_dir(path) else {
        return false;
    };
    let mut seen = 0usize;
    for entry in entries {
        let Ok(entry) = entry else { return false };
        let Ok(kind) = entry.file_type() else {
            return false;
        };
        if !previous
            .iter()
            .any(|(name, saved_kind)| *name == entry.file_name() && *saved_kind == kind)
        {
            return false;
        }
        seen += 1;
        if seen > previous.len() {
            return false;
        }
    }
    seen == previous.len()
}

pub(super) fn root(files: &NativeStateFiles, retain: bool) -> AtlasResult<(u64, Inventory)> {
    let mut entries = 0;
    let mut bytes = 0;
    let mut snapshot = Inventory {
        directories: Vec::new(),
        files: Vec::new(),
        complete: true,
    };
    let total = walk(
        files,
        2,
        files.root(),
        &mut bytes,
        &mut entries,
        &mut snapshot,
        retain,
    )?;
    if !snapshot.complete {
        snapshot.files.clear();
        snapshot.directories.clear();
    }
    Ok((total, snapshot))
}
fn walk(
    files: &NativeStateFiles,
    depth: u8,
    wanted: &Path,
    root: &mut u64,
    entries: &mut u32,
    snapshot: &mut Inventory,
    retain: bool,
) -> AtlasResult<u64> {
    let mut total = 0u64;
    let mut epoch_count = 0;
    // A missing sentinel is a native check of the original retained directory;
    // it is never created. Entry reads repeat that custody check themselves.
    let mut names = Vec::new();
    let mut names_complete = true;
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
        if names.len() < MAX_RETAINED_FILES {
            names.push((entry.file_name(), kind));
        } else {
            names_complete = false;
            snapshot.complete = false;
        }
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
            walk(&child, depth + 1, wanted, root, entries, snapshot, retain)?
        } else {
            let allowed = NativeStateFiles::is_recovery_artifact(&entry.file_name())
                || match depth {
                    0 => name == "writer.lock",
                    2 => matches!(name.as_str(), "current.json" | "reservation.json"),
                    4 => matches!(name.as_str(), "atlas.db" | "atlas.db-wal" | "atlas.db-shm"),
                    _ => false,
                };
            if !allowed || !kind.is_file() {
                return Err(fail(
                    "unknown or linked Atlas cache entry preserved; inspect before growth",
                ));
            }
            let pin = files
                .pin_metadata(&path)
                .map_err(fail)?
                .ok_or_else(|| fail("Atlas inventory file disappeared"))?;
            let len = pin.metadata().map_err(fail)?.len();
            if snapshot.files.len() < MAX_RETAINED_FILES {
                snapshot.files.push(InventoryFile::new(path, pin, retain)?);
            } else {
                snapshot.complete = false;
            }
            len
        };
        total = total
            .checked_add(size)
            .ok_or_else(|| fail("Atlas inventory byte overflow"))?;
    }
    files
        .readback(&files.root().join(".atlas-inventory-check"))
        .map_err(fail)?;
    if names_complete && !entries_match(files.root(), &names) {
        return Err(fail("Atlas inventory directory changed during measurement"));
    }
    snapshot
        .directories
        .push((NativeStateFiles::open(files.root()).map_err(fail)?, names));
    if files.root() == wanted {
        *root = total
    }
    Ok(total)
}
