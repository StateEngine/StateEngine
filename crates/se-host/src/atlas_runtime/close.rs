//! Optional derived watch metadata, after native custody has already closed.
use super::*;
impl<D: RenewalDriver> NativeRuntime<D> {
    pub(super) fn persist_closed(&mut self, id: &RootId, deadline: Instant) -> AtlasResult<()> {
        let scope = self
            .roots
            .iter()
            .find(|r| &r.summary.root == id)
            .filter(|r| !r.needs_rebuild)
            .map(|r| r.source.scope.clone());
        let cache = if let (Some(scope), Some(_), true) =
            (&scope, self.profile.as_ref(), self.active.is_none())
        {
            let opened = NativeAtlasCache::open(&self.home, scope.clone())?;
            if opened
                .as_ref()
                .map(|cache| cache.read_pointer())
                .transpose()?
                .flatten()
                .is_some()
            {
                Some(NativeAtlasCache::create(&self.home, scope.clone())?)
            } else {
                None
            }
        } else {
            None
        };
        let mut current =
            if let (Some(cache), Some(profile), Some(scope)) = (&cache, &self.profile, &scope) {
                let known = self
                    .roots
                    .iter()
                    .find(|r| &r.summary.root == id)
                    .and_then(|r| r.checked_epoch.as_ref());
                let published = cache
                    .read_pointer()?
                    .map(|bytes| pointer::decode(&bytes, scope).map(|p| p.epoch))
                    .transpose()?;
                if let Some(epoch) = known.filter(|epoch| Some(*epoch) == published.as_ref()) {
                    // This owner already checked the whole exact epoch at activation
                    // or adoption. Keep scope/schema/native checks on close without
                    // repeating a graph-wide scan inside the finite drain clock.
                    pointer::open_checked_writer(cache, scope, profile, epoch, deadline)?
                } else {
                    // Explicit close may follow an unannounced pointer change.
                    // Validate that epoch independently before closing its durable
                    // watch state; renewal must still refuse the old serial domain.
                    let checked = pointer::open_current(
                        cache,
                        scope,
                        ConnectionRole::CandidateReader,
                        profile,
                        deadline,
                    )?;
                    let epoch = checked
                        .as_ref()
                        .map(|current| current.connection.identity().epoch.clone());
                    drop(checked);
                    epoch
                        .map(|epoch| {
                            pointer::open_checked_writer(cache, scope, profile, &epoch, deadline)
                        })
                        .transpose()?
                        .flatten()
                }
            } else {
                None
            };
        if let Some(current) = &mut current {
            self.driver
                .close(id, Some(&mut current.connection), deadline)?;
        }
        Ok(())
    }
}
