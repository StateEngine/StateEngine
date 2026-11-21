use super::*;
use crate::state_files::NativeStateFiles;
use std::path::{Component, PathBuf};

/// Only successfully published native directory objects enter this custody.
/// The handles remain retained through installer completion and failed-child
/// cleanup. Dropping it closes handles; it never silently deletes directories.
pub struct NativeDirectoryCreation {
    created: Vec<os::CreatedDirectory>,
}
pub struct CreatedDirectoryCleanup {
    pub path: PathBuf,
    pub result: Result<DirectoryRemoval>,
}
impl NativeDirectoryCreation {
    pub fn begin() -> Self {
        Self {
            created: Vec::new(),
        }
    }
    pub fn create(&mut self, root: &Path) -> Result<NativeStateFiles> {
        self.prepare(root)?;
        NativeStateFiles::open(root)
    }
    /// Prepare an installation directory without imposing private-store read
    /// permissions on an existing shared per-user executable directory.
    /// Ownership, no-follow traversal and exclusion of foreign writers remain required.
    pub fn prepare(&mut self, root: &Path) -> Result<()> {
        if !root.is_absolute()
            || root.components().any(|part| {
                !matches!(
                    part,
                    Component::Prefix(_) | Component::RootDir | Component::Normal(_)
                )
            })
        {
            return Err(failure(
                StateFileErrorCode::LocationUnsafe,
                "normalized absolute installer state home required",
                root,
            ));
        }
        let mut prefix = PathBuf::new();
        for part in root.components() {
            prefix.push(part);
            if matches!(part, Component::Normal(_)) {
                os::prepare_created_directory(&prefix, &mut self.created)?;
            }
        }
        os::validate_creation_target(root)
    }
    pub fn paths(&self) -> Vec<PathBuf> {
        self.created
            .iter()
            .map(|directory| directory.path().to_owned())
            .collect()
    }
    /// Deepest first, using the exact retained native identity. Nonempty,
    /// replaced or unreadable objects remain named, never counted as removed.
    pub fn rollback(&mut self) -> Vec<CreatedDirectoryCleanup> {
        self.created
            .iter()
            .rev()
            .map(|directory| CreatedDirectoryCleanup {
                path: directory.path().to_owned(),
                result: directory.cleanup(),
            })
            .collect()
    }
}
