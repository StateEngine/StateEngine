//! Duplicate only admitted object pins into the native child's finite inventory.
use super::*;

#[derive(serde::Serialize)]
pub(super) struct Entry {
    handle: u64,
    path: PathBuf,
    kind: &'static str,
    identity: String,
    sha256: Option<String>,
}
type Original<'a> = (&'a File, &'a Path, &'static str, Option<[u8; 32]>);

pub(super) struct Inventory {
    pub handles: Vec<OwnedHandle>,
    pub entries: Vec<Entry>,
}
impl Inventory {
    pub fn new(
        originals: [Original<'_>; 3],
        directories: &[String],
        parents: [Option<&Path>; 2],
    ) -> Result<Self> {
        let mut value = Self {
            handles: Vec::new(),
            entries: Vec::new(),
        };
        for (file, path, kind, digest) in originals {
            value.retain(file, path, kind, digest)?;
        }
        for path in directories.iter().map(Path::new) {
            if let Some(file) =
                crate::state_files::windows::effects::uninstall_directory(path).map_err(custody)?
            {
                value.retain(&file, path, "directory", None)?;
            }
        }
        for path in parents.into_iter().flatten() {
            let file = crate::state_files::windows::effects::uninstall_directory(path)
                .map_err(custody)?
                .ok_or_else(|| refuse("prepare uninstall carrier", "original parent absent"))?;
            value.retain(&file, path, "flush", None)?;
        }
        Ok(value)
    }
    fn retain(
        &mut self,
        file: &File,
        path: &Path,
        kind: &'static str,
        sha: Option<[u8; 32]>,
    ) -> Result<()> {
        let copy = native::duplicate_same(file.as_raw_handle(), true)?;
        let identity = super::entry_effects::identity(file, matches!(kind, "directory" | "flush"))?;
        self.entries.push(Entry {
            handle: copy.as_raw_handle() as usize as u64,
            path: path.to_owned(),
            kind,
            identity,
            sha256: sha.map(|value| se_types::hex_lower(&value)),
        });
        self.handles.push(copy);
        Ok(())
    }
}
