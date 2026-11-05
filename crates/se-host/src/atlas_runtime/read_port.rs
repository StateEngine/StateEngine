//! One owner-installed read port. No root activation, SQL connection, worker or
//! authoritative snapshot is created by this handoff.
use super::{NativeController, RenewalDriver, record_fence::*};
use crate::atlas_source::NativeAtlasSource;
use se_atlas::{
    cache::connection::CacheConnection, lifecycle::AtlasController, source::RegisteredSource,
};
use se_types::{
    ProjectId, Result, SeError,
    code::{IndexSummary, RootId},
};
use std::sync::{Arc, Mutex, OnceLock};

pub type AtlasReadCallback<'a> =
    dyn FnMut(&CacheConnection<'_>, &RegisteredSource<NativeAtlasSource>, bool) -> Result<()> + 'a;
/// Object-safe owner-loop handoff. The callback runs synchronously while the
/// selected controller lends its one scoped reader; nothing escapes the call.
pub trait AtlasReadPort: Send + Sync {
    fn summary(&self, project: &ProjectId, root: Option<&RootId>) -> Result<IndexSummary>;
    fn with_reader(
        &self,
        project: &ProjectId,
        root: Option<&RootId>,
        read: &mut AtlasReadCallback<'_>,
    ) -> Result<()>;
}
#[derive(Default)]
pub struct AtlasOwnerPort {
    reader: OnceLock<Arc<dyn AtlasReadPort>>,
    pub records: Arc<RecordFeedFence>,
}
impl AtlasOwnerPort {
    pub fn summary(&self, project: &ProjectId, root: Option<&RootId>) -> Result<IndexSummary> {
        self.reader.get().ok_or_else(|| se_core::scope::unreadable("Atlas owner read port", "the owner has not installed its controller; no registered root summary is available"))?.summary(project, root)
    }
    pub(crate) fn install(&self, reader: Arc<dyn AtlasReadPort>) -> Result<()> {
        self.reader.set(reader).map_err(|_| {
            SeError::invalid(
                "Atlas read port",
                "one controller installation before host publication",
            )
        })
    }
    /// Capture ticket before the core query snapshot. This check occurs after
    /// that snapshot opens, so an intervening committed write cannot appear fresh.
    pub fn with_reader(
        &self,
        project: &ProjectId,
        root: Option<&RootId>,
        ticket: Option<RecordFeedTicket>,
        read: &mut AtlasReadCallback<'_>,
    ) -> Result<()> {
        let reader = self.reader.get().ok_or_else(|| se_core::scope::unreadable("Atlas owner read port", "the owner has not installed its controller; queries cannot open a substitute cache"))?;
        reader.with_reader(project, root, &mut |cache, source, _| {
            read(
                cache,
                source,
                self.records
                    .is_current(&RecordFeedScope::from(cache.identity()), ticket)?,
            )
        })
    }
}
/// Shared only with the native owner's event driver. Query callers cannot
/// install a second controller or bypass registered-project root selection.
pub struct ControllerReadPort<D> {
    pub controller: Arc<Mutex<NativeController<D>>>,
}
impl<D: RenewalDriver + Send> AtlasReadPort for ControllerReadPort<D> {
    fn summary(&self, project: &ProjectId, root: Option<&RootId>) -> Result<IndexSummary> {
        let controller=self.controller.try_lock().map_err(|_|se_core::scope::unreadable("Atlas owner controller", "the owner is busy or its controller lock is poisoned; retry after the active finite quantum"))?;
        let root = controller.registered_root(project, root)?;
        controller.summary(&root)
    }
    fn with_reader(
        &self,
        project: &ProjectId,
        root: Option<&RootId>,
        read: &mut AtlasReadCallback<'_>,
    ) -> Result<()> {
        let controller = self.controller.try_lock().map_err(|_| se_core::scope::unreadable("Atlas owner controller", "the owner is busy or its controller lock is poisoned; retry after the active finite quantum"))?;
        let root = controller.registered_root(project, root)?;
        controller.with_reader(root, |cache, source| read(cache, source, false))
    }
}
