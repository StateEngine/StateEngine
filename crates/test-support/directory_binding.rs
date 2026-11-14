use std::{
    io,
    path::{Path, PathBuf},
};

/// Retained native directory identities keep pathname drift from authorizing
/// removal of a different tree. Canonicalization resolves initial temp aliases;
/// every physical ancestor and the created root stay pinned until cleanup.
pub(super) struct Binding {
    roots: Vec<se_proc::NativeSourceRoot>,
}
impl Binding {
    pub(super) fn capture(path: &Path) -> io::Result<(PathBuf, Self)> {
        if !path.is_absolute() || path.file_name().is_none() {
            return Err(io::Error::other(
                "an absolute created fixture root is required",
            ));
        }
        // Inspect the original final entry before resolving ancestor aliases.
        // NativeSourceRoot rejects a final symbolic link or reparse point.
        let original = se_proc::NativeSourceRoot::open(path)?;
        let identity = original.physical_identity()?;
        let path = se_proc::canonicalize_path(path)?;
        let mut roots = Vec::new();
        for ancestor in path.ancestors() {
            roots.push(se_proc::NativeSourceRoot::open(ancestor)?);
        }
        let binding = Self { roots };
        if binding.identity()? != identity {
            return Err(io::Error::other(
                "fixture root changed while binding cleanup",
            ));
        }
        binding.check()?;
        Ok((path, binding))
    }
    pub(super) fn identity(&self) -> io::Result<[u8; 32]> {
        self.roots
            .first()
            .ok_or_else(|| io::Error::other("fixture root binding is absent"))?
            .physical_identity()
    }
    pub(super) fn check(&self) -> io::Result<()> {
        // Start at the filesystem root before inspecting descendants.
        for root in self.roots.iter().rev() {
            root.check()?;
        }
        Ok(())
    }
}
