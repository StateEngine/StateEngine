use super::{id, leaf, parent};
use crate::state_files::{
    Result,
    effects::{absent, changed},
};
use std::{
    ffi::CString,
    fs::File,
    path::{Path, PathBuf},
};

pub(in crate::state_files) struct ReadPin {
    path: PathBuf,
    directory: File,
    name: CString,
    file: File,
    identity: (u64, u64),
}
impl ReadPin {
    pub(in crate::state_files) fn open(path: &Path) -> Result<Option<Self>> {
        let (directory, name) = match parent(path) {
            Ok(value) => value,
            Err(error) if absent(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let file = match leaf(&directory, &name, path, false) {
            Ok(file) => file,
            Err(error) if absent(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let identity = id(&file, path, false, true)?;
        let pin = Self {
            path: path.into(),
            directory,
            name,
            file,
            identity,
        };
        pin.check()?;
        Ok(Some(pin))
    }
    pub(in crate::state_files) fn file(&self) -> &File {
        &self.file
    }
    pub(in crate::state_files) fn identity(&self) -> Vec<u8> {
        self.identity
            .0
            .to_le_bytes()
            .into_iter()
            .chain(self.identity.1.to_le_bytes())
            .collect()
    }
    pub(in crate::state_files) fn check(&self) -> Result<()> {
        let (current_parent, _) = parent(&self.path)?;
        if id(&current_parent, &self.path, true, false)?
            != id(&self.directory, &self.path, true, false)?
        {
            return Err(changed("transcript parent identity changed", &self.path));
        }
        let named = leaf(&self.directory, &self.name, &self.path, false)?;
        if id(&named, &self.path, false, true)? != self.identity
            || id(&self.file, &self.path, false, true)? != self.identity
        {
            return Err(changed(
                "transcript pathname no longer names the retained source",
                &self.path,
            ));
        }
        Ok(())
    }
}
