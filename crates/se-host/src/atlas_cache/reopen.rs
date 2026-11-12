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
    pub(super) fn writer_lease(home: &NativeStateFiles) -> AtlasResult<writer::WriterLease> {
        let path = home.root().join("writer.lock");
        let writer = home
            .readback(&path)
            .map_err(fail)?
            .ok_or_else(|| fail("writer lock absent"))?;
        // The shared guard takes the same exclusive nonblocking lock and keeps
        // its exact refusal distinct: a contended lease is a retryable busy.
        // Windows excludes through the exclusive open itself, so it keeps the
        // plain descriptor and releases by close.
        #[cfg(unix)]
        let writer = match se_proc::advisory_lock::AdvisoryLock::acquire(writer) {
            Ok(guard) => guard,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(busy("Atlas home writer lease", 1, 0));
            }
            Err(error) => return Err(fail(error)),
        };
        let named = home
            .readback(&path)
            .map_err(fail)?
            .ok_or_else(|| fail("writer lock replaced"))?;
        if !same(writer::opened(&writer), &named)? {
            return Err(fail("writer lock identity changed"));
        }
        Ok(writer)
    }
}
