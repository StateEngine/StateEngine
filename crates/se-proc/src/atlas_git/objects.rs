//! Refuse linked object names; retain directory revisions across the helper read.
//! Landlock independently prevents foreign reads during namespace races.
use super::*;
use crate::{NativeFileRevision, NativeSourceKind, NativeSourceRoot};
pub(super) struct Fence(Vec<(String, NativeFileRevision)>);
impl Fence {
    pub(super) fn open(root: &NativeSourceRoot, deadline: Instant) -> io::Result<Self> {
        let mut pending = vec![String::new()];
        let mut directories = Vec::new();
        let mut count = 0;
        while let Some(path) = pending.pop() {
            if directories.len() == 259 {
                return Err(invalid(
                    "Git object directory count exceeds 259; repack the repository",
                ));
            }
            let mut cursor = root
                .open_directory(&path)?
                .ok_or_else(|| invalid("Git object directory disappeared"))?;
            let revision = cursor.revision()?;
            loop {
                let batch = cursor.next_batch()?;
                if batch.is_empty() {
                    break;
                }
                for entry in batch {
                    count += 1;
                    if count > 100_000 || Instant::now() >= deadline {
                        return Err(invalid(
                            "Git no-follow object inspection exceeds its entry/deadline bound; repack or retry",
                        ));
                    }
                    let name = entry
                        .name
                        .to_str()
                        .ok_or_else(|| invalid("Git object name is not UTF-8"))?;
                    match entry.kind {
                        NativeSourceKind::File => (),
                        NativeSourceKind::Directory
                            if path.is_empty()
                                && (name == "pack"
                                    || name == "info"
                                    || (name.len() == 2
                                        && name.bytes().all(|b| b.is_ascii_hexdigit()))) =>
                        {
                            pending.push(name.into())
                        }
                        _ => {
                            return Err(invalid(
                                "Git object names must be regular no-follow files in standard fanout, pack or info directories",
                            ));
                        }
                    }
                }
            }
            if cursor.revision()? != revision {
                return Err(invalid("Git object names changed during inspection; retry"));
            }
            directories.push((path, revision));
        }
        Ok(Self(directories))
    }
    pub(super) fn check(&self, root: &NativeSourceRoot) -> io::Result<()> {
        for (path, revision) in &self.0 {
            let cursor = root
                .open_directory(path)?
                .ok_or_else(|| invalid("Git object directory disappeared during read"))?;
            if &cursor.revision()? != revision {
                return Err(invalid("Git object namespace changed during read; retry"));
            }
        }
        Ok(())
    }
}
