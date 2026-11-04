use crate::{errors::AtlasResult, model::*};
use se_types::{AgentId, Page, Read};

// Requests, results and pure text validation use the shared code contract.
pub use se_types::code::{
    AtlasFormat, AtlasTarget, AtlasText, AtlasValidation, ChangeBaseline, ChangesQuery, FeedRecord,
    FindQuery, GitObjectId, ImpactQuery, OutlineQuery, RecordFeed, RecordFeedChange, ReferenceHit,
    RefsQuery, ResumeAdvance, ResumeChange, ResumeCode, ResumeCodeState, ResumeCursorCommit,
    ResumeOfferId, ResumeRequest, SearchHit, SearchKind, SearchMode, SearchOrder, SearchScope,
    SymbolSelector,
};

/// Implemented by the host adapter to core's private cursor store.
/// Delivery must identify a successful context delivery, not mere construction.
pub trait ResumeCursorStore {
    fn compare_and_set(
        &mut self,
        viewer: &AgentId,
        delivered: &se_types::EventId,
        advance: &ResumeAdvance,
    ) -> AtlasResult<ResumeCursorCommit>;
}

/// Bound by the host to one registered project/worktree and authorized source
/// scope. These methods never enable, open-for-write, index or launch anything.
pub trait AtlasQueries {
    fn find(&self, query: &FindQuery) -> AtlasResult<Answer<Read<se_types::code::SearchResults>>>;
    fn refs(&self, query: &RefsQuery) -> AtlasResult<Answer<Read<Page<ReferenceHit>>>>;
    fn impact(&self, query: &ImpactQuery) -> AtlasResult<Answer<Read<Impact>>>;
    fn changes(&self, query: &ChangesQuery) -> AtlasResult<Answer<Read<Page<CodeChange>>>>;
    fn outline(&self, query: &OutlineQuery) -> AtlasResult<Answer<Read<Outline>>>;
    fn resume_code(&self, request: &ResumeRequest) -> AtlasResult<ResumeCode>;
    fn status(&self) -> IndexSummary;
}
