use super::*;
use crate::state_files::NativeStateFiles;
use std::path::PathBuf;

impl NativeStateFiles {
    /// Complete finite inventory within this retained private root. Every
    /// returned leaf has the same native no-follow/owner/private-file checks
    /// as readback; an unsafe or unreadable entry refuses the whole inventory.
    /// Directories are not followed or silently treated as owned files.
    pub fn list_owned(&self, directory: &Path) -> Result<Vec<PathBuf>> {
        self.check(directory)?;
        let names = os::list_names(directory)?;
        for path in &names {
            if path.to_str().is_none() {
                return Err(failure(
                    StateFileErrorCode::Unsupported,
                    "owned inventory pathname is not lossless UTF-8",
                    path,
                ));
            }
            let file = self
                .pin_metadata(path)?
                .ok_or_else(|| changed("owned inventory entry disappeared", path))?;
            // Recheck each protected native identity immediately; this grants
            // no later deletion authority to the list.
            let identity = file.identity()?;
            let outside = self
                .pin_metadata(path)?
                .ok_or_else(|| changed("owned inventory entry disappeared on readback", path))?;
            if outside.identity()? != identity {
                return Err(changed(
                    "owned inventory entry changed during readback",
                    path,
                ));
            }
        }
        if os::list_names(directory)? != names {
            return Err(changed(
                "owned directory inventory changed during validation",
                directory,
            ));
        }
        self.check(directory)?;
        Ok(names)
    }
}
