//! One owner-installed read port. No root activation, SQL connection, worker or
//! authoritative snapshot is created by this handoff. Explicit queries may
//! notify the existing background owner of project interest.
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

pub type AtlasReadCallback<'a> = dyn FnMut(&mut CacheConnection<'_>, &RegisteredSource<NativeAtlasSource>, bool) -> Result<()>
    + 'a;
pub struct AtlasReadObservation {
    pub summary: IndexSummary,
    pub epoch_retired: bool,
    /// Filled by AtlasOwnerPort against the authoritative query snapshot.
    pub record_feed_current: bool,
}
pub type AtlasObservedReadCallback<'a> = dyn FnMut(
        &mut CacheConnection<'_>,
        &RegisteredSource<NativeAtlasSource>,
        AtlasReadObservation,
    ) -> Result<()>
    + 'a;
/// Object-safe owner-loop handoff. The callback runs synchronously while the
/// selected controller lends its one scoped reader; nothing escapes the call.
pub trait AtlasReadPort: Send + Sync {
    /// Current project roots from the caller's authoritative read snapshot.
    fn observe_project(&self, _project: &ProjectId, _roots: &[se_store::Root]) -> Result<()> {
        Ok(())
    }
    /// Signal an admitted query's project without doing native work here.
    fn request_interest(&self, _project: &ProjectId, _root: Option<&RootId>) -> Result<()> {
        Ok(())
    }
    fn summary(&self, project: &ProjectId, root: Option<&RootId>) -> Result<IndexSummary>;
    /// Status observes publication only; no cache opens or work is scheduled.
    fn status(
        &self,
        project: &ProjectId,
        root: Option<&RootId>,
    ) -> Result<se_types::Read<IndexSummary>> {
        self.summary(project, root)
            .map(|value| se_types::Read::Present { value })
    }
    fn with_reader(
        &self,
        project: &ProjectId,
        root: Option<&RootId>,
        read: &mut AtlasReadCallback<'_>,
    ) -> Result<()>;
    /// Borrowing controllers observe before lending their reader, avoiding
    /// recursive owner locking. The native service observes after admission.
    fn with_observed_reader(
        &self,
        project: &ProjectId,
        root: Option<&RootId>,
        read: &mut AtlasObservedReadCallback<'_>,
    ) -> Result<()> {
        let summary = self.summary(project, root)?;
        self.with_reader(project, root, &mut |cache, source, epoch_retired| {
            read(
                cache,
                source,
                AtlasReadObservation {
                    summary: summary.clone(),
                    epoch_retired,
                    record_feed_current: false,
                },
            )
        })
    }
}
#[derive(Default)]
pub struct AtlasOwnerPort {
    reader: OnceLock<Arc<dyn AtlasReadPort>>,
    pub records: Arc<RecordFeedFence>,
}
impl AtlasOwnerPort {
    pub(crate) fn observe_project(
        &self,
        project: &ProjectId,
        roots: &[se_store::Root],
    ) -> Result<()> {
        if let Some(reader) = self.reader.get() {
            reader.observe_project(project, roots)?;
        }
        Ok(())
    }
    #[cfg(feature = "listener")]
    pub(crate) fn is_installed(&self) -> bool {
        self.reader.get().is_some()
    }
    pub fn status(
        &self,
        project: &ProjectId,
        root: Option<&RootId>,
    ) -> Result<se_types::Read<IndexSummary>> {
        match self.reader.get() {
            Some(reader) => reader.status(project, root),
            None => Ok(se_types::Read::Absent {
                checked: "No Atlas controller is installed in this host.".into(),
            }),
        }
    }
    pub(crate) fn request_interest(
        &self,
        project: &ProjectId,
        root: Option<&RootId>,
    ) -> Result<()> {
        if let Some(reader) = self.reader.get() {
            reader.request_interest(project, root)?;
        }
        Ok(())
    }
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
        self.with_observed_reader(project, root, ticket, &mut |cache, source, observed| {
            read(cache, source, observed.record_feed_current)
        })
    }
    pub(crate) fn with_observed_reader(
        &self,
        project: &ProjectId,
        root: Option<&RootId>,
        ticket: Option<RecordFeedTicket>,
        read: &mut AtlasObservedReadCallback<'_>,
    ) -> Result<()> {
        let reader = self.reader.get().ok_or_else(|| se_core::scope::unreadable("Atlas owner read port", "the owner has not installed its controller; queries cannot open a substitute cache"))?;
        reader.with_observed_reader(project, root, &mut |cache, source, mut observed| {
            observed.record_feed_current = self
                .records
                .is_current(&RecordFeedScope::from(cache.identity()), ticket)?;
            read(cache, source, observed)
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
