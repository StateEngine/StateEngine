//! One owner-installed read port. No root activation, worker or authoritative
//! snapshot is created by this handoff. Explicit queries may notify the
//! existing background owner of project interest.
use super::record_fence::*;
use se_types::{
    ProjectId, Result, SeError,
    code::{IndexSummary, RootId},
};
use std::sync::{Arc, OnceLock};

/// Object-safe owner-loop handoff: summaries and the v5 engine for admitted
/// queries. No cache connection is lent across this boundary.
pub trait AtlasReadPort: Send + Sync {
    /// A retained disabled controller still serves explicit availability errors.
    fn is_enabled(&self) -> bool {
        true
    }
    /// Current project roots from the caller's authoritative read snapshot.
    fn observe_project(&self, _project: &ProjectId, _roots: &[se_store::Root]) -> Result<()> {
        Ok(())
    }
    /// Signal an admitted query's project without doing native work here.
    fn request_interest(&self, _project: &ProjectId, _root: Option<&RootId>) -> Result<()> {
        Ok(())
    }
    fn summary(&self, project: &ProjectId, root: Option<&RootId>) -> Result<IndexSummary>;
    /// The v5 engine serving this project's selected worktree.
    fn engine(
        &self,
        _project: &ProjectId,
        _root: Option<&RootId>,
    ) -> Result<Arc<se_atlas_service::Root>> {
        Err(se_core::scope::unreadable(
            "Atlas engine",
            "this controller has no v5 engine; restart the host",
        ))
    }
    /// Status observes publication only; no cache opens or work is scheduled.
    fn status(
        &self,
        project: &ProjectId,
        root: Option<&RootId>,
    ) -> Result<se_types::Read<IndexSummary>> {
        self.summary(project, root)
            .map(|value| se_types::Read::Present { value })
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
    pub fn is_available(&self) -> bool {
        self.reader.get().is_some_and(|reader| reader.is_enabled())
    }
    pub fn status(
        &self,
        project: &ProjectId,
        root: Option<&RootId>,
    ) -> Result<se_types::Read<IndexSummary>> {
        match self.reader.get() {
            Some(reader) => reader.status(project, root),
            None => Ok(se_types::Read::Absent {
                checked: "No Atlas controller is installed in this host. Run the standalone host with `se up` to enable Atlas.".into(),
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
        self.reader
            .get()
            .ok_or_else(no_controller)?
            .summary(project, root)
    }
    /// The engine an admitted query reads; never starts indexing itself.
    pub fn engine(
        &self,
        project: &ProjectId,
        root: Option<&RootId>,
    ) -> Result<Arc<se_atlas_service::Root>> {
        self.reader
            .get()
            .ok_or_else(no_controller)?
            .engine(project, root)
    }
    #[cfg(feature = "listener")]
    pub fn install(&self, reader: Arc<dyn AtlasReadPort>) -> Result<()> {
        self.reader.set(reader).map_err(|_| {
            SeError::invalid(
                "Atlas read port",
                "one controller installation before host publication",
            )
        })
    }
}
fn no_controller() -> SeError {
    SeError::new(se_types::Detail::FeatureUnavailable(
        se_types::details::FeatureUnavailable {
            subject: "Atlas".into(),
            reason: "no Atlas controller is installed in this host".into(),
            next_step:
                "Run the standalone host with `se up` using the same --home to enable Atlas.".into(),
        },
    ))
}

#[cfg(all(test, feature = "listener"))]
mod availability_tests {
    use super::*;
    struct Stub(bool);
    impl AtlasReadPort for Stub {
        fn is_enabled(&self) -> bool {
            self.0
        }
        fn summary(&self, _: &ProjectId, _: Option<&RootId>) -> Result<IndexSummary> {
            Err(se_core::scope::unreadable("stub", "no summary"))
        }
    }
    /// Bug: PR 186 — a retained disabled controller advertised Atlas tools.
    #[test]
    fn availability_follows_installation_and_the_controller_switch() -> Result<()> {
        let absent = AtlasOwnerPort::default();
        assert!(!absent.is_available(), "no controller installed");
        let disabled = AtlasOwnerPort::default();
        disabled.install(Arc::new(Stub(false)))?;
        assert!(!disabled.is_available(), "disabled controller advertised");
        let enabled = AtlasOwnerPort::default();
        enabled.install(Arc::new(Stub(true)))?;
        assert!(enabled.is_available(), "enabled controller hidden");
        Ok(())
    }

    #[test]
    fn absent_controller_refuses_with_feature_unavailable_and_actionable_status() -> Result<()> {
        let absent = AtlasOwnerPort::default();
        let project = ProjectId::from_parts(1, [7; 10])?;
        let status = absent.status(&project, None)?;
        assert!(
            matches!(status, se_types::Read::Absent { checked } if checked.contains("No Atlas controller") && checked.contains("se up")),
            "absent controller status must name the missing controller and a working next step"
        );
        for result in [
            absent.summary(&project, None).map(|_| ()),
            absent.engine(&project, None).map(|_| ()),
        ] {
            let error = result.err().ok_or_else(|| {
                SeError::invalid(
                    "absent controller",
                    "an explicit FeatureUnavailable refusal",
                )
            })?;
            assert!(
                matches!(
                    error.body.detail(),
                    se_types::Detail::FeatureUnavailable(detail)
                        if detail.next_step.contains("se up")
                ),
                "unexpected absent controller error: {error:?}"
            );
        }
        Ok(())
    }
}
