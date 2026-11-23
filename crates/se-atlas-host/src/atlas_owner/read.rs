//! The owner's read port: summaries and engines for admitted queries. No
//! query starts a build; registering a worktree only starts its writer.
use super::*;
use crate::atlas_runtime::read_port::{AtlasReadCallback, AtlasReadPort};
use se_types::code::{IndexState, IndexSummary};

impl Service {
    fn disabled_summary(spec: &RootSpec) -> IndexSummary {
        IndexSummary {
            project: spec.project.clone(),
            root: spec.root.clone(),
            epoch: None,
            generation: None,
            state: IndexState::Disabled,
            coverage: crate::atlas_cold::empty_coverage(),
            memory: None,
        }
    }
}

impl AtlasReadPort for Service {
    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn observe_project(&self, project: &ProjectId, roots: &[se_store::Root]) -> Result<()> {
        let changed = self.register(project, roots::specs(project, roots, &self.home)?)?;
        if changed && self.enabled {
            self.interests.wake_owner();
        }
        Ok(())
    }

    fn request_interest(&self, project: &ProjectId, _root: Option<&RootId>) -> Result<()> {
        if self.enabled {
            self.interests.interest(project)?;
        }
        Ok(())
    }

    fn status(
        &self,
        project: &ProjectId,
        selected: Option<&RootId>,
    ) -> Result<se_types::Read<IndexSummary>> {
        let registered = self
            .roots()?
            .iter()
            .any(|registered| &registered.spec.project == project);
        if !registered {
            return Ok(se_types::Read::Unknown {
                what: "Atlas has not observed this project's registration yet; a query starts indexing and status shows progress.".into(),
            });
        }
        self.summary(project, selected)
            .map(|value| se_types::Read::Present { value })
    }

    fn summary(&self, project: &ProjectId, selected: Option<&RootId>) -> Result<IndexSummary> {
        match self.select(project, selected)? {
            (_, Some(root)) => root.summary(),
            (spec, None) => Ok(Self::disabled_summary(&spec)),
        }
    }

    fn engine(&self, project: &ProjectId, selected: Option<&RootId>) -> Result<Arc<Root>> {
        self.select(project, selected)?.1.ok_or_else(|| {
            SeError::invalid(
                "Atlas reader",
                "an enabled registered root; set [atlas] enabled = true and restart the host",
            )
        })
    }

    fn with_reader(
        &self,
        _: &ProjectId,
        _: Option<&RootId>,
        _: &mut AtlasReadCallback<'_>,
    ) -> Result<()> {
        Err(SeError::invalid(
            "Atlas reader",
            "the v5 engine; this host no longer lends legacy cache connections",
        ))
    }
}
