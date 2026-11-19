//! Metadata admission retains the namespace proof, never mutable permissions.
use super::*;

impl Directory {
    pub fn admit_metadata(&self, path: &Path, root: &Path) -> Result<bool> {
        if path.parent() != Some(root) || !local_ntfs(&self.file) {
            return Ok(false);
        }
        // The directory pin already denies delete sharing before this walk.
        // On local NTFS, its nonempty ordinary ancestors cannot be renamed or
        // acquire a reparse point while the descendant directory remains open.
        // Existing reparse ancestry keeps the full traversal on every read.
        let (found, ordinary) = walk_with_ancestry(root, false, None, self.layout, false)?;
        self.same_metadata_root(&found, root)?;
        Ok(ordinary)
    }

    pub fn check_trusted_ancestry(&self, root: &Path) -> Result<()> {
        let (found, _) = walk_with_ancestry(root, false, None, self.layout, true)?;
        self.same_metadata_root(&found, root)
    }

    pub fn check_metadata_name(&self, root: &Path) -> Result<()> {
        let found = open(root, true, false, true)?;
        self.same_metadata_root(&found, root)
    }

    pub(in crate::state_files) fn same_metadata_root(
        &self,
        found: &File,
        root: &Path,
    ) -> Result<()> {
        if metadata_for(found, root, true, self.layout)? != self.identity {
            return Err(failure(
                StateFileErrorCode::SourceChanged,
                "held state directory was replaced",
                root,
            ));
        }
        metadata_for(&self.file, root, true, self.layout)?;
        Ok(())
    }

    pub fn read_admitted_metadata(&self, path: &Path, root: &Path) -> Result<Option<File>> {
        self.check_metadata_name(root)?;
        let file = match open(&self.absolute(path, root)?, false, false, false) {
            Ok(file) => file,
            Err(error)
                if error
                    .source
                    .as_ref()
                    .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        metadata_for(&file, path, false, self.layout)?;
        Ok(Some(file))
    }
}

fn local_ntfs(file: &File) -> bool {
    let mut path = vec![0u16; 32768];
    // SAFETY: retained directory handle and bounded writable UTF-16 output.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_GUID,
        )
    } as usize;
    if length == 0 || length >= path.len() {
        return false;
    }
    let Ok(path) = String::from_utf16(&path[..length]) else {
        return false;
    };
    if !path.starts_with(r"\\?\Volume{") || !path.contains("}\\") {
        return false;
    }
    let mut filesystem = [0u16; 16];
    // SAFETY: live directory handle, unused optional outputs are null, and the
    // filesystem-name output has its exact writable capacity. An unsupported
    // qualification retains full validation rather than guessing a volume type.
    let present = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    };
    present != 0
        && filesystem[..5]
            == [
                u16::from(b'N'),
                u16::from(b'T'),
                u16::from(b'F'),
                u16::from(b'S'),
                0,
            ]
}
