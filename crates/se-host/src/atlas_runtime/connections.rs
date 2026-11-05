use super::*;
impl<D: RenewalDriver> NativeRuntime<D> {
    pub fn poll_events(&mut self, id: &RootId, deadline: Instant) -> AtlasResult<Vec<SourceHint>> {
        if self.active.is_some() {
            return Err(atlas_cold::failure(
                "cold child owns the home writer; preserve native readiness until reap",
            ));
        }
        let root = self.root(id)?;
        let profile = self
            .profile
            .as_ref()
            .ok_or_else(|| atlas_cold::failure("native host SQL profile is unqualified"))?;
        let cache = NativeAtlasCache::create(&self.home, root.source.scope.clone())?;
        let current = pointer::open_current(
            &cache,
            &root.source.scope,
            ConnectionRole::HostWriter,
            profile,
            deadline,
        )?
        .ok_or_else(|| atlas_cold::failure("watch event cache is absent"))?;
        let root = self
            .roots
            .iter()
            .find(|r| &r.summary.root == id)
            .ok_or_else(|| atlas_cold::failure("native root disappeared"))?;
        self.driver
            .poll_events(&root.source, &current.connection, &root.policy, deadline)
    }
    #[cfg(unix)]
    pub fn event_fd(&self, id: &RootId) -> Option<std::os::fd::BorrowedFd<'_>> {
        self.driver.event_fd(id)
    }
    pub fn with_writer<T>(
        &self,
        root: &RootId,
        deadline: Instant,
        write: impl FnOnce(&CacheConnection<'_>, &RegisteredSource<NativeAtlasSource>) -> AtlasResult<T>,
    ) -> AtlasResult<T> {
        if self.active.is_some() {
            return Err(atlas_cold::failure(
                "cold child owns the root; coalesce hints until reap",
            ));
        }
        let root = self.root(root)?;
        let profile = self.profile.as_ref().ok_or_else(|| {
            atlas_cold::failure("native host SQL profile is unqualified; incremental work deferred")
        })?;
        let cache = NativeAtlasCache::create(&self.home, root.source.scope.clone())?;
        let discovered = pointer::open_current(
            &cache,
            &root.source.scope,
            ConnectionRole::HostWriter,
            profile,
            deadline,
        )?
        .ok_or_else(|| {
            atlas_cold::failure("root index is absent; after-ready cold activation required")
        })?;
        write(&discovered.connection, &root.source)
    }
    pub fn with_reader<T>(
        &self,
        root: &RootId,
        read: impl FnOnce(&CacheConnection<'_>, &RegisteredSource<NativeAtlasSource>) -> AtlasResult<T>,
    ) -> AtlasResult<T> {
        let root = self.root(root)?;
        let profile = self
            .profile
            .as_ref()
            .ok_or_else(|| atlas_cold::failure("native host SQL profile is unqualified"))?;
        let cache = NativeAtlasCache::open(&self.home, root.source.scope.clone())?
            .ok_or_else(|| atlas_cold::failure("root index is absent"))?;
        let discovered = pointer::open_current(
            &cache,
            &root.source.scope,
            ConnectionRole::HostReader,
            profile,
            atlas_cold::sql_deadline(),
        )?
        .ok_or_else(|| atlas_cold::failure("root index pointer is absent"))?;
        read(&discovered.connection, &root.source)
    }
}
