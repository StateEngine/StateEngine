//! Hold an unpublished cold database in its validated local namespace.
use super::*;
use std::os::windows::fs::OpenOptionsExt;

pub(super) struct PrivateGuard {
    pub path: PathBuf,
    pub active: bool,
    _namespace: se_proc::NativeMetadataPin,
    _file: File,
}

impl NativeAtlasCache {
    pub(super) fn guard_private_creation(
        &self,
        connection: &se_atlas::cache::connection::NativeSqlConnection,
    ) -> AtlasResult<()> {
        let Some((epoch, reserved)) = self.reserved.borrow().clone() else {
            return Ok(());
        };
        let Some(pin) = self.pin_database(&epoch)? else {
            return Err(fail("reserved cold database is absent"));
        };
        let parent = pin
            .path
            .parent()
            .ok_or_else(|| fail("cold database parent absent"))?;
        let directory = NativeStateFiles::open(parent).map_err(fail)?;
        let Some(namespace) = directory.pin_metadata(&pin.path).map_err(fail)? else {
            return Err(fail("cold database name disappeared"));
        };
        if !namespace.is_ordinary_local() {
            return Ok(());
        }
        // Deny delete sharing until the cold connection is closed.
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .share_mode(0x0000_0001 | 0x0000_0002)
            .custom_flags(0x0020_0000)
            .open(&pin.path)
        {
            Ok(file) => file,
            Err(_) => return Ok(()),
        };
        let revision = observe_file_revision(&file).map_err(fail)?;
        let identity = (revision.volume, revision.file);
        if identity != reserved
            || namespace.identity().map_err(fail)? != identity
            || pin.file.identity().map_err(fail)? != identity
        {
            return Err(fail("private cold database identity changed"));
        }
        let sqlite = match se_proc::NativeFileIdentity::observe_sqlite(connection) {
            Ok(identity) => identity,
            Err(_) => return Ok(()),
        };
        let named = se_proc::NativeFileIdentity::observe(&pin.path).map_err(fail)?;
        if sqlite != named {
            return Err(fail("SQLite opened a different cold database"));
        }
        self.validate_database(&pin)?;
        *self.private_guard.borrow_mut() = Some(PrivateGuard {
            path: pin.path,
            active: true,
            _namespace: namespace,
            _file: file,
        });
        Ok(())
    }

    /// Resume full validation while retaining the guard through finalization.
    pub(crate) fn finish_private_creation(&self) {
        if let Some(guard) = self.private_guard.borrow_mut().as_mut() {
            guard.active = false;
        }
    }
}
