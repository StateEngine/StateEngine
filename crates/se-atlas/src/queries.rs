use crate::{errors::AtlasResult, model::*};
use se_types::{AgentId, Page, Read};

#[derive(Debug)]
pub struct SearchScope {
    pub paths: Vec<RelativePath>,
    pub languages: Vec<Language>,
}
#[derive(Debug)]
pub enum SymbolSelector {
    Id(SymbolId),
    At {
        path: RelativePath,
        position: Position,
    },
    Name {
        name: QueryText,
        path: Option<RelativePath>,
        container: Option<QueryText>,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchKind {
    Symbol,
    Text,
    Path,
}
#[derive(Debug)]
pub struct FindQuery {
    pub kind: SearchKind,
    pub query: QueryText,
    pub scope: SearchScope,
    pub next: Option<AtlasCursor>,
    pub budget: QueryBudget,
}
#[derive(Debug)]
pub struct RefsQuery {
    pub symbol: SymbolSelector,
    pub kinds: Vec<ReferenceKind>,
    pub include_name_only: bool,
    pub next: Option<AtlasCursor>,
    pub budget: QueryBudget,
}
#[derive(Debug)]
pub struct ImpactQuery {
    pub symbol: SymbolSelector,
    pub depth: u8,
    pub include_name_only: bool,
    pub next: Option<AtlasCursor>,
    pub budget: QueryBudget,
}
#[derive(Debug)]
pub enum GitObjectId {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}
#[derive(Debug)]
pub enum ChangeBaseline {
    Cursor(AtlasCursor),
    ObservedCommit(GitObjectId),
    ObservedUnixMillis(i64),
}
#[derive(Debug)]
pub struct ChangesQuery {
    pub since: ChangeBaseline,
    pub scope: SearchScope,
    pub next: Option<AtlasCursor>,
    pub budget: QueryBudget,
}
#[derive(Debug)]
pub struct OutlineQuery {
    pub path: RelativePath,
    pub next: Option<AtlasCursor>,
    pub budget: QueryBudget,
}

#[derive(Debug)]
pub struct ResumeRequest {
    pub viewer: AgentId,
    pub saved_cursor: Option<AtlasCursor>,
    pub recently_edited_symbols: Vec<SymbolId>,
}
#[derive(Debug)]
pub enum ResumeCodeState {
    Available,
    Zero,
    NeverIndexed,
    Disabled,
    Unreadable,
    BaselineGap,
    Updating,
    BudgetExceeded,
}
#[derive(Debug)]
pub struct ResumeCode {
    pub index: IndexSummary,
    pub state: ResumeCodeState,
    pub text: String,
    pub pointers: Vec<CodePointer>,
    pub returned: u8,
    pub omitted: Option<u64>,
    pub complete: bool,
    pub offered_cursor: Option<AtlasCursor>,
    pub diagnostic: Option<crate::errors::AtlasError>,
}

/// Bound by the host to one registered project/worktree and authorized source
/// scope. These methods never enable, open-for-write, index or launch anything.
pub trait AtlasQueries {
    fn find(&self, query: &FindQuery) -> AtlasResult<Read<Answer<Page<CodeHit>>>>;
    fn refs(&self, query: &RefsQuery) -> AtlasResult<Read<Answer<Page<Reference>>>>;
    fn impact(&self, query: &ImpactQuery) -> AtlasResult<Read<Answer<Impact>>>;
    fn changes(&self, query: &ChangesQuery) -> AtlasResult<Read<Answer<Page<CodeChange>>>>;
    fn outline(&self, query: &OutlineQuery) -> AtlasResult<Read<Answer<Outline>>>;
    fn resume_code(&self, request: &ResumeRequest) -> AtlasResult<ResumeCode>;
    fn status(&self) -> IndexSummary;
}

/// Required constructors/decoders, declared without implementation until design
/// approval. JSON/CLI adapters call these same validations.
pub trait AtlasValidation {
    fn relative_path(&self, value: String) -> AtlasResult<RelativePath>;
    fn query_text(&self, value: String) -> AtlasResult<QueryText>;
    fn cursor(&self, value: String) -> AtlasResult<AtlasCursor>;
    fn query_budget(&self, results: u16, bytes: u32) -> AtlasResult<QueryBudget>;
    fn selector(&self, value: SymbolSelector) -> AtlasResult<SymbolSelector>;
}

/// Implemented for RelativePath, AtlasCursor and QueryText after approval.
pub trait AtlasText {
    fn as_str(&self) -> &str;
}
