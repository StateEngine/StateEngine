//! Bounded directory enumeration over retained native source handles.
use super::*;

/// An owned finite directory stream can survive a host work quantum. Its root
/// and directory pins remain bound; no borrowed source or raw pathname escapes.
pub struct NativeWatchDirectory {
    root: NativeSourceRoot,
    path: String,
    directory: File,
    identity: NativeFileRevision,
    entries: entries::Cursor,
}
impl NativeWatchDirectory {
    pub fn open(root: &NativeSourceRoot, path: &str) -> io::Result<Option<Self>> {
        let Some(pin) = root.open_directory(path)? else {
            return Ok(None);
        };
        let owned_root = NativeSourceRoot {
            path: root.path.clone(),
            directory: root.directory.try_clone()?,
            identity: root.identity.clone(),
        };
        let NativeRootDirectory {
            path,
            directory,
            identity,
            entries,
            ..
        } = pin;
        Ok(Some(Self {
            root: owned_root,
            path,
            directory,
            identity,
            entries,
        }))
    }
    pub fn physical_identity(&self) -> io::Result<[u8; 32]> {
        if !self.validate_name()? {
            return Err(changed("enumerated directory changed"));
        }
        Ok(self.identity.root_key())
    }
    pub fn path(&self) -> &str {
        &self.path
    }
    pub fn validate_name(&self) -> io::Result<bool> {
        self.root.check()?;
        let named = if self.path.is_empty() {
            os::open_root(&self.root.path)
        } else {
            os::open_directory(&self.root.directory, &self.path)
        };
        let named = match named {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        let same = self.identity.same_object(&os::revision(&named, true)?)
            && self
                .identity
                .same_object(&os::revision(&self.directory, true)?);
        self.root.check()?;
        Ok(same)
    }
    pub fn next_entry(&mut self) -> io::Result<Option<NativeSourceEntry>> {
        if !self.validate_name()? {
            return Err(changed("enumerated directory changed"));
        }
        let entry = self.entries.next()?;
        if !self.validate_name()? {
            return Err(changed("enumerated directory changed"));
        }
        Ok(entry)
    }
}
