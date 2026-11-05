//! The writer publishes bounded root metadata, never a borrowed SQL handle.
//! Foreground reads open the published WAL epoch without taking its work lock.
use super::*;
use crate::{atlas_cache::NativeAtlasCache, atlas_source::NativeAtlasSource};
use se_atlas::cache::{CacheFiles, connection::ConnectionRole, pointer};

#[derive(Default)]
pub(super) struct Catalogue {
    roots: Vec<Root>,
}
impl Catalogue {
    pub(super) fn clear(&mut self) {
        self.roots.clear();
    }
}
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
            if !working {
                self.work.publish(&root.registration, summary.clone())?;
            }
            roots.push(Root {
                registration: root.registration.clone(),
                summary,
            });
        }
        *self.readers.lock().map_err(|_| poisoned())? = Catalogue { roots };
        Ok(())
    }
    fn reader_root(&self, project: &ProjectId, selected: Option<&RootId>) -> Result<Root> {
        let mut roots = self
            .work
            .roots(project)?
            .into_iter()
            .filter(|root| selected.is_none_or(|id| id == &root.registration.root));
        let root = roots.next().ok_or_else(|| {
            SeError::invalid(
                "Atlas query root",
                "a current registered worktree of this project",
            )
        })?;
        if roots.next().is_some() {
            return Err(SeError::invalid(
                "Atlas query root",
                "an explicit root when the project has several worktrees",
            ));
        }
        if root.registration.cache.directory
            != self
                .home
                .join(project.as_str())
                .join(root.registration.root.as_str())
        {
            return Err(SeError::invalid(
                "Atlas reader cache",
                "the fixed project/root directory",
            ));
        }
        if let Some(live) = self
            .readers
            .lock()
            .map_err(|_| poisoned())?
            .roots
            .iter()
            .find(|live| {
                live.registration.root == root.registration.root
                    && live.registration.canonical_source_root
                        == root.registration.canonical_source_root
            })
        {
            return Ok(live.clone());
        }
        let registration = root.registration;
        let mut summary = root.summary.unwrap_or_else(|| IndexSummary {
            project: project.clone(),
            root: registration.root.clone(),
            memory: Some(self.memory.clone()),
            epoch: None,
            generation: None,
            state: IndexState::Opening,
            coverage: crate::atlas_cold::empty_coverage(),
        });
        if !self.enabled {
            summary.state = IndexState::Disabled;
        } else {
            let source = NativeAtlasSource::open(registration.clone(), CaseMode::Sensitive)?;
            let pointer = NativeAtlasCache::open(&self.home, source.scope.clone())?
                .map(|cache| cache.read_pointer())
                .transpose()?
                .flatten()
                .map(|bytes| pointer::decode(&bytes, &source.scope))
                .transpose()?;
            let epoch = pointer
                .filter(|pointer| pointer.schema == se_atlas::cache::schema::SCHEMA_VERSION)
                .map(|pointer| pointer.epoch);
            if summary.epoch != epoch {
                summary.generation = None;
                summary.coverage = crate::atlas_cold::empty_coverage();
                summary.state = IndexState::Opening;
            }
            summary.epoch = epoch;
            if !matches!(
                summary.state,
                IndexState::Partial { .. }
                    | IndexState::Suspended { .. }
                    | IndexState::Unreadable { .. }
            ) {
                summary.state = if summary.epoch.is_some() {
                    IndexState::VerificationNeeded {
                        reason: CoverageReason::StaleSnapshot,
                    }
                } else {
                    IndexState::Opening
                };
            }
            summary.coverage.watched_directories = 0;
            summary.coverage.watch_discovery_complete = false;
            if !summary
                .coverage
                .reasons
                .contains(&CoverageReason::StaleSnapshot)
            {
                summary.coverage.reasons.push(CoverageReason::StaleSnapshot);
            }
        }
        summary.memory = Some(self.memory.clone());
        Ok(Root {
            registration,
            summary,
        })
    }
}
impl AtlasReadPort for Service {
    fn observe_project(&self, project: &ProjectId, roots: &[se_store::Root]) -> Result<()> {
        self.work
            .register(project, roots::registrations(project, roots, &self.home)?)
    }
    fn request_interest(&self, project: &ProjectId) -> Result<()> {
        if self.enabled {
            let needs_catch_up = {
                let roots = self.readers.lock().map_err(|_| poisoned())?;
                !roots.roots.iter().any(|root| {
                    &root.registration.project == project
                        && !matches!(
                            root.summary.state,
                            IndexState::Suspended { .. } | IndexState::Unreadable { .. }
                        )
                })
            };
            if needs_catch_up {
                self.work.request(project)?;
            }
            self.interests.interest(project)?;
            if needs_catch_up {
                self.interests.wake_owner();
            }
        }
        Ok(())
    }
    fn status(
        &self,
        project: &ProjectId,
        selected: Option<&RootId>,
    ) -> Result<se_types::Read<IndexSummary>> {
        if self.work.roots(project)?.is_empty() {
            return Ok(se_types::Read::Unknown { what: "Atlas has not observed this project's registration yet; a query starts indexing and status shows progress.".into() });
        }
        self.summary(project, selected)
            .map(|value| se_types::Read::Present { value })
    }
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
