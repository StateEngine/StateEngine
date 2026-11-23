#![allow(dead_code)]
//! Shared fixtures, poll helpers, and record-check doubles for Atlas service acceptance tests.

use se_atlas_service::{FeedReceipt, RecordCheck, Root, RootSpec};
use se_types::{
    AgentId, EventId, Page, ProjectId, Read,
    code::{
        Answer, AtlasCursor, AtlasPrincipal, AtlasTarget, AtlasText as _, ChangeBaseline,
        ChangesQuery, CodeChange, CodeCursorPosition, CoverageReason, CursorKey, FeedRecord,
        FindQuery, Generation, HitTarget, ImpactQuery, IndexState, IndexSummary, MentionTarget,
        OutlineQuery, QueryBudget, QueryText, RecordFeed, RecordFeedChange, RecordHit, RecordKey,
        RecordKind, RecordPointer, RecordVisibility, RelativePath, RootId, SearchKind, SearchOrder,
        SearchResults, SearchScope, cursor_digest,
    },
};
use std::{
    collections::HashMap,
    fs, io,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub type TestResult = Result<(), Box<dyn std::error::Error>>;

pub const SETTLE_TIMEOUT: Duration = Duration::from_secs(5);
pub const QUERY_TIMEOUT: Duration = Duration::from_secs(4);
pub const STOP_TIMEOUT: Duration = Duration::from_secs(4);

pub struct TempDir {
    path: PathBuf,
    links: Vec<PathBuf>,
}

impl TempDir {
    pub fn new(label: &str) -> io::Result<Self> {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "se-atlas-service-accept-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path)?;
        #[cfg(unix)]
        let path = fs::canonicalize(&path)?;
        Ok(Self {
            path,
            links: Vec::new(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn join(&self, relative: &str) -> PathBuf {
        relative
            .split('/')
            .fold(self.path.clone(), |acc, part| acc.join(part))
    }

    pub fn write(&self, relative: &str, text: &str) -> io::Result<()> {
        let full = self.join(relative);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(full, text.as_bytes())
    }

    pub fn add_dir_link(&mut self, relative: &str, target: &Path) -> io::Result<PathBuf> {
        let link = self.join(relative);
        if let Some(parent) = link.parent() {
            fs::create_dir_all(parent)?;
        }
        #[cfg(windows)]
        {
            let output = std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&link)
                .arg(target)
                .output()?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(io::Error::other(format!("mklink /J failed: {stderr}")));
            }
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, &link)?;
        }
        self.links.push(link.clone());
        Ok(link)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // Remove directory links before recursive teardown so external targets are untouched.
        for link in self.links.drain(..) {
            #[cfg(windows)]
            let _ = fs::remove_dir(&link);
            #[cfg(unix)]
            let _ = fs::remove_file(&link);
        }
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub struct LiveRoot {
    pub repo: TempDir,
    pub state: TempDir,
    pub spec: RootSpec,
    pub root: Option<Arc<Root>>,
}

impl LiveRoot {
    pub fn start(label: &str, files: &[(&str, &str)]) -> Result<Self, Box<dyn std::error::Error>> {
        let repo = TempDir::new(&format!("{label}-repo"))?;
        let state = TempDir::new(&format!("{label}-state"))?;
        for (path, text) in files {
            repo.write(path, text)?;
        }
        Self::start_in(repo, state)
    }

    pub fn start_in(repo: TempDir, state: TempDir) -> Result<Self, Box<dyn std::error::Error>> {
        let spec = RootSpec {
            project: project_id(1)?,
            root: root_id(1)?,
            source: repo.path().to_path_buf(),
            directory: state.path().to_path_buf(),
        };
        let root = Root::start(spec.clone())?;
        Ok(Self {
            repo,
            state,
            spec,
            root: Some(root),
        })
    }

    pub fn root(&self) -> Result<&Root, Box<dyn std::error::Error>> {
        self.root
            .as_deref()
            .ok_or_else(|| io::Error::other("root already stopped").into())
    }

    pub fn stop(&mut self, timeout: Duration) -> TestResult {
        if let Some(root) = self.root.take() {
            root.stop(timeout)?;
        }
        Ok(())
    }

    pub fn restart(&mut self) -> TestResult {
        self.stop(STOP_TIMEOUT)?;
        self.root = Some(Root::start(self.spec.clone())?);
        Ok(())
    }
}

impl Drop for LiveRoot {
    fn drop(&mut self) {
        if let Some(root) = self.root.take() {
            let _ = root.stop(STOP_TIMEOUT);
        }
    }
}

pub fn project_id(n: u8) -> se_types::Result<ProjectId> {
    ProjectId::from_parts(1_700_000_000_000, [n; 10])
}

pub fn root_id(n: u8) -> se_types::Result<RootId> {
    RootId::from_parts(1_700_000_000_000, [n; 10])
}

pub fn agent_id(n: u8) -> se_types::Result<AgentId> {
    AgentId::from_parts(1_700_000_000_000, [n; 10])
}

pub fn event_id(seq: u64) -> se_types::Result<EventId> {
    let mut entropy = [0u8; 10];
    entropy[2..].copy_from_slice(&seq.to_be_bytes());
    EventId::from_parts(1_700_000_000_000 + seq, entropy)
}

pub fn budget(max_results: u16, max_bytes: u32) -> se_types::Result<QueryBudget> {
    QueryBudget {
        max_results,
        max_bytes,
        work: Duration::from_millis(250),
    }
    .checked()
}

pub fn empty_scope() -> SearchScope {
    SearchScope {
        paths: Vec::new(),
        languages: Vec::new(),
    }
}

pub fn find_query(
    kind: SearchKind,
    text: &str,
    query_budget: QueryBudget,
    next: Option<AtlasCursor>,
) -> se_types::Result<FindQuery> {
    Ok(FindQuery {
        kind,
        query: QueryText::new(text)?,
        scope: empty_scope(),
        next,
        budget: query_budget,
        mode: None,
        order: SearchOrder::Relevance,
        full: false,
        regex: false,
    })
}

pub fn outline_query(path: &str) -> se_types::Result<OutlineQuery> {
    Ok(OutlineQuery {
        path: RelativePath::new(path)?,
        next: None,
        budget: budget(100, 65_536)?,
    })
}

pub fn impact_query(path: &str) -> se_types::Result<ImpactQuery> {
    Ok(ImpactQuery {
        target: AtlasTarget::File(RelativePath::new(path)?),
        depth: 2,
        include_name_only: false,
        next: None,
        budget: budget(50, 65_536)?,
    })
}

pub fn changes_query(
    since: ChangeBaseline,
    max_results: u16,
    next: Option<AtlasCursor>,
) -> se_types::Result<ChangesQuery> {
    Ok(ChangesQuery {
        since,
        scope: empty_scope(),
        next,
        budget: budget(max_results, 65_536)?,
    })
}

pub fn present<T>(read: Read<T>) -> Result<T, Box<dyn std::error::Error>> {
    match read {
        Read::Present { value } => Ok(value),
        Read::Absent { checked } => Err(format!("expected Present, got Absent({checked})").into()),
        Read::Unreadable { source, reason, .. } => {
            Err(format!("expected Present, got Unreadable({source}: {reason})").into())
        }
        Read::Unknown { what } => Err(format!("expected Present, got Unknown({what})").into()),
    }
}

pub fn wait_until<T>(
    timeout: Duration,
    label: &str,
    mut check: impl FnMut() -> Result<Option<T>, Box<dyn std::error::Error>>,
) -> Result<T, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = check()? {
            return Ok(value);
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for {label} after {timeout:?}").into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

pub fn wait_current(
    root: &Root,
    timeout: Duration,
) -> Result<IndexSummary, Box<dyn std::error::Error>> {
    wait_until(timeout, "IndexState::Current", || {
        let summary = root.summary()?;
        if summary.state == IndexState::Current {
            Ok(Some(summary))
        } else {
            Ok(None)
        }
    })
}

pub fn wait_generation_gt(
    root: &Root,
    after: u64,
    timeout: Duration,
) -> Result<IndexSummary, Box<dyn std::error::Error>> {
    wait_until(timeout, "generation advance and Current", || {
        let summary = root.summary()?;
        let generation = summary.generation.map_or(0, |g| g.0);
        if summary.state == IndexState::Current && generation > after {
            Ok(Some(summary))
        } else {
            Ok(None)
        }
    })
}

pub fn wait_find_path(root: &Root, term: &str, expected_path: &str) -> TestResult {
    wait_until(QUERY_TIMEOUT, expected_path, || {
        let query = find_query(SearchKind::All, term, budget(20, 65_536)?, None)?;
        let res = present(root.find(&query, &DenyAllRecords)?.data)?;
        Ok(code_hit_paths(&res)
            .iter()
            .any(|p| p == expected_path)
            .then_some(()))
    })?;
    Ok(())
}

pub fn epoch_db_path(state_dir: &Path) -> io::Result<PathBuf> {
    let pointer = fs::read_to_string(state_dir.join("atlas.v5.current"))?;
    Ok(state_dir.join(pointer.trim()))
}

pub fn code_hit_paths(results: &SearchResults) -> Vec<String> {
    results
        .page
        .items()
        .iter()
        .filter_map(|hit| match &hit.target {
            HitTarget::Code(code) => Some(code.pointer.path.as_str().to_owned()),
            _ => None,
        })
        .collect()
}

pub fn record_hit_keys(results: &SearchResults) -> Vec<String> {
    results
        .page
        .items()
        .iter()
        .filter_map(|hit| match &hit.target {
            HitTarget::Record(record) => Some(record.pointer.key.as_str().to_owned()),
            _ => None,
        })
        .collect()
}

pub fn range_cursor_for(
    index: &IndexSummary,
    viewer: &AtlasPrincipal,
    delivered: u64,
    fence: Option<Generation>,
) -> se_types::Result<AtlasCursor> {
    CodeCursorPosition::new(
        index,
        "changes-range",
        cursor_digest(&("changes-range", viewer))?,
        CursorKey {
            integers: vec![delivered, u64::from(u32::MAX)],
            bytes: Vec::new(),
        },
        fence,
    )?
    .encode()
}

pub fn change_generation(change: &CodeChange) -> u64 {
    match change {
        CodeChange::Edit(edit) => edit.id.generation.0,
        CodeChange::Bulk(bulk) => bulk.id.generation.0,
    }
}

pub struct DenyAllRecords;

impl RecordCheck for DenyAllRecords {
    fn hit(
        &self,
        _pointer: &RecordPointer,
        _query: Option<&QueryText>,
    ) -> se_types::Result<Read<RecordHit>> {
        Ok(Read::Absent {
            checked: "test record store".into(),
        })
    }
}

pub struct MapRecordCheck {
    entries: HashMap<String, Read<RecordHit>>,
}

impl MapRecordCheck {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn allow(&mut self, hit: RecordHit) {
        self.entries.insert(
            hit.pointer.key.as_str().to_owned(),
            Read::Present { value: hit },
        );
    }
}

impl RecordCheck for MapRecordCheck {
    fn hit(
        &self,
        pointer: &RecordPointer,
        _query: Option<&QueryText>,
    ) -> se_types::Result<Read<RecordHit>> {
        Ok(self
            .entries
            .get(pointer.key.as_str())
            .cloned()
            .unwrap_or_else(|| Read::Absent {
                checked: "test record authority".into(),
            }))
    }
}

pub struct UnreadableRecordCheck;

impl RecordCheck for UnreadableRecordCheck {
    fn hit(
        &self,
        _pointer: &RecordPointer,
        _query: Option<&QueryText>,
    ) -> se_types::Result<Read<RecordHit>> {
        Ok(Read::Unreadable {
            source: "core record authority".into(),
            reason: "injected authority read failure".into(),
            error: None,
        })
    }
}

pub struct SeedSpec<'a> {
    pub key: &'a str,
    pub event_seq: u64,
    pub occurred_unix_ms: i64,
    pub title: &'a str,
    pub body: &'a str,
    pub visibility: RecordVisibility,
    pub mentions: Vec<MentionTarget>,
}

pub fn build_record_pair(
    project: &ProjectId,
    spec: SeedSpec<'_>,
) -> se_types::Result<(FeedRecord, RecordHit)> {
    let pointer = RecordPointer {
        key: RecordKey::new(spec.key)?,
        kind: RecordKind::Message,
        source_event: event_id(spec.event_seq)?,
    };
    let hit = RecordHit {
        pointer: pointer.clone(),
        actor: None,
        occurred_unix_ms: spec.occurred_unix_ms,
        line: format!("{}: {}", spec.title, spec.body),
        body_truncated: false,
        mentions: spec.mentions.clone(),
    };
    let feed = FeedRecord {
        pointer,
        project: project.clone(),
        actor: None,
        occurred_unix_ms: spec.occurred_unix_ms,
        title: spec.title.into(),
        visibility: spec.visibility,
        body: spec.body.into(),
        body_truncated: false,
        mentions: spec.mentions,
    };
    Ok((feed, hit))
}

pub fn feed_batch(
    root: &Root,
    project: &ProjectId,
    after: Option<EventId>,
    through: EventId,
    records: Vec<FeedRecord>,
) -> se_types::Result<FeedReceipt> {
    let feed = RecordFeed {
        project: project.clone(),
        after,
        through,
        changes: records.into_iter().map(RecordFeedChange::Upsert).collect(),
        complete: true,
    };
    root.apply_feed(feed, Duration::from_secs(5))
}

pub struct CollectedChanges {
    pub items: Vec<CodeChange>,
    pub reasons: Vec<CoverageReason>,
    pub pages: usize,
}

pub fn collect_all_changes(
    root: &Root,
    since: ChangeBaseline,
    viewer: &AtlasPrincipal,
    max_results: u16,
) -> Result<CollectedChanges, Box<dyn std::error::Error>> {
    let mut cursor: Option<AtlasCursor> = None;
    let mut items = Vec::new();
    let mut reasons = Vec::new();
    let mut pages = 0usize;
    loop {
        let query = changes_query(since.clone(), max_results, cursor.clone())?;
        let answer: Answer<Read<Page<CodeChange>>> = root.changes(&query, viewer)?;
        for reason in answer.index.coverage.reasons {
            if !reasons.contains(&reason) {
                reasons.push(reason);
            }
        }
        let page = present(answer.data)?;
        pages += 1;
        let next = page
            .next()
            .map(|c| AtlasCursor::new(c.as_str()))
            .transpose()?;
        if next.is_some() {
            assert!(
                !page.items().is_empty(),
                "non-final changes page {pages} must not be empty"
            );
            assert_ne!(next, cursor, "changes cursor must progress");
        }
        items.extend(page.items().iter().cloned());
        if next.is_none() {
            assert!(
                page.window().complete(),
                "final changes page must be complete"
            );
            break;
        }
        cursor = next;
    }
    Ok(CollectedChanges {
        items,
        reasons,
        pages,
    })
}
