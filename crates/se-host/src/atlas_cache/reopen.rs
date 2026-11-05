//! Repeated finite work reopens existing private directories without rerunning
//! initialization's directory fsyncs. Writer custody and inventory still renew.
use super::*;

impl NativeAtlasCache {
    pub(super) fn reopen(home: &Path, scope: Scope) -> AtlasResult<Option<Self>> {
        let Some(mut cache) = Self::open(home, scope)? else {
            return Ok(None);
        };
        match NativeStateFiles::open(&cache.root.root().join("epochs")) {
            Ok(_) => (),
            Err(error) if missing(&error) => return Ok(None),
            Err(error) => return Err(fail(error)),
        }
        if cache
            .home
            .readback(&cache.home.root().join("writer.lock"))
            .map_err(fail)?
            .is_none()
        {
            return Ok(None);
        }
        cache.writer = Some(Self::writer_lease(&cache.home)?);
        cache.recover_reservation()?;
        Ok(Some(cache))
    }
    pub(super) fn writer_lease(home: &NativeStateFiles) -> AtlasResult<File> {
        let path = home.root().join("writer.lock");
        let writer = home
            .readback(&path)
            .map_err(fail)?
            .ok_or_else(|| fail("writer lock absent"))?;
        writer.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => busy("Atlas home writer lease", 1, 0),
            std::fs::TryLockError::Error(error) => fail(error),
        })?;
        let named = home
            .readback(&path)
            .map_err(fail)?
            .ok_or_else(|| fail("writer lock replaced"))?;
        if !same(&writer, &named)? {
            return Err(fail("writer lock identity changed"));
        }
        Ok(writer)
    }
}
