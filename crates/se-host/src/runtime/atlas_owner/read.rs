//! The writer publishes bounded root metadata, never a borrowed SQL handle.
//! Foreground reads open the published WAL epoch without taking its work lock.
use super::*;
use crate::{atlas_cache::NativeAtlasCache, atlas_source::NativeAtlasSource};
use se_atlas::cache::{connection::ConnectionRole, pointer};

#[derive(Clone)]
pub(super) struct Root {
    registration: RootRegistration,
    summary: IndexSummary,
}
pub(super) fn poisoned() -> SeError {
    se_core::scope::unreadable(
        "Atlas reader catalogue",
        "the catalogue lock is poisoned; restart the host without removing its caches",
    )
}
impl Service {
    pub(super) fn publish_readers(&self, state: &State, working: bool) -> Result<()> {
        let mut roots = Vec::with_capacity(state.roots.len());
        for root in &state.roots {
            let mut summary = state.controller.summary(&root.registration.root)?;
            summary.memory = Some(self.memory.clone());
            if working && matches!(summary.state, IndexState::Current) {
                summary.state = IndexState::VerificationNeeded {
                    reason: CoverageReason::StaleSnapshot,
                };
            }
            roots.push(Root {
                registration: root.registration.clone(),
                summary,
            });
        }
        *self.readers.lock().map_err(|_| poisoned())? = roots;
        Ok(())
    }
    fn reader_root(&self, project: &ProjectId, selected: Option<&RootId>) -> Result<Root> {
        let roots = self.readers.lock().map_err(|_| poisoned())?;
        let mut matching = roots.iter().filter(|root| {
            &root.registration.project == project
                && selected.is_none_or(|id| id == &root.registration.root)
        });
        let root = matching.next().ok_or_else(|| {
            SeError::invalid(
                "Atlas query root",
                "a registered root of the admitted project; registration may still be opening",
            )
        })?;
        if matching.next().is_some() {
            return Err(SeError::invalid(
                "Atlas query root",
                "an explicit root when the admitted project has several worktrees",
            ));
        }
        Ok(root.clone())
    }
}
impl AtlasReadPort for Service {
    fn summary(&self, project: &ProjectId, selected: Option<&RootId>) -> Result<IndexSummary> {
        Ok(self.reader_root(project, selected)?.summary)
    }
    fn with_reader(
        &self,
        project: &ProjectId,
        selected: Option<&RootId>,
        read: &mut AtlasReadCallback<'_>,
    ) -> Result<()> {
        self.with_observed_reader(project, selected, &mut |cache, source, observed| {
            read(cache, source, observed.epoch_retired)
        })
    }
    fn with_observed_reader(
        &self,
        project: &ProjectId,
        selected: Option<&RootId>,
        read: &mut AtlasObservedReadCallback<'_>,
    ) -> Result<()> {
        let root = self.reader_root(project, selected)?;
        if matches!(
            root.summary.state,
            IndexState::Disabled | IndexState::Closed | IndexState::Draining
        ) {
            return Err(SeError::invalid(
                "Atlas reader",
                "an enabled, open registered root",
            ));
        }
        let profile = self.profile.as_ref().ok_or_else(|| {
            SeError::invalid(
                "Atlas SQL profile",
                "a native-qualified reader profile for this platform",
            )
        })?;
        let source = NativeAtlasSource::open(root.registration, CaseMode::Sensitive)?;
        let home = source
            .scope
            .registration
            .cache
            .directory
            .parent()
            .and_then(|path| path.parent())
            .ok_or_else(|| {
                SeError::invalid(
                    "Atlas reader home",
                    "the fixed project/root cache directory",
                )
            })?;
        let cache = NativeAtlasCache::open(home, source.scope.clone())?.ok_or_else(|| {
            se_core::scope::unreadable("Atlas cache", "the published root cache is absent")
        })?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let current = pointer::open_current(
            &cache,
            &source.scope,
            ConnectionRole::QueryReader,
            profile,
            deadline,
        )?
        .ok_or_else(|| {
            se_core::scope::unreadable(
                "Atlas pointer",
                "the registered root has no published epoch",
            )
        })?;
        let observed = self.reader_root(project, Some(&source.scope.registration.root))?;
        read(
            &current.connection,
            &source,
            AtlasReadObservation {
                summary: observed.summary,
                epoch_retired: current.epoch_retired,
                record_feed_current: false,
            },
        )
    }
}
