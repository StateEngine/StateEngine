//! A captured provider tool edit must reach v5 Atlas edit activity as one
//! queryable record attributed to the capturing agent, and nothing else.
//! This test commits a real transcript session — preparation, activation,
//! a capture source, one tool-bearing turn plus its progress marker —
//! through the public store writer, feeds the committed history through
//! the host record-chunk contract, and queries the result through the v5
//! Atlas find path as both the author and an unrelated agent. The exact
//! committed SQLite row shape is asserted directly.

#![cfg(all(
    feature = "listener",
    any(target_os = "linux", target_os = "macos", windows)
))]

#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(dead_code, reason = "only the typed session helpers are used")]
mod capture_fixture;
#[path = "../../se-store/tests/support/host_fixture.rs"]
#[allow(dead_code, reason = "only the host writer helper is used")]
mod host_fixture;
#[path = "../../se-atlas-service/tests/support/mod.rs"]
mod support;

use se_atlas_host::{
    atlas_owner::records::{Fed, chunk},
    atlas_records::AtlasRecordReader,
    atlas_runtime::record_fence::{RecordFeedFence, RecordFeedScope},
    host::{AtlasHost, BoxedWork, HostFuture},
};
use se_atlas_service::{RecordCheck, Root, RootSpec};
use se_core::{
    admission::read_scope,
    ops::transcript::{
        Position, Record,
        tool::{
            NativeIdentity, Observation, ObservedPath, Outcome, Phase, SCHEMA, Target, ToolName,
        },
    },
    scope,
    store_error::store_error,
};
use se_store::*;
use se_types::{
    AgentId, EventId, Generation, NativePath, ProjectId, Read, SeError, SessionId,
    code::{
        AtlasActor, AtlasPrincipal, HitTarget, QueryText, RecordHit, RecordKey, RecordKind,
        RecordPointer, SearchHit, SearchKind,
    },
};
use sha2::{Digest, Sha256};
use std::{
    any::Any,
    error::Error,
    fs,
    num::NonZeroU32,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const SERVICE_FILE: &str = "src/service.rs";
const SERVICE_SOURCE: &str = "pub fn serve() -> &'static str { \"public\" }\n";
const DESCRIPTION: &str = "Captured native file edit succeeded; current-content author unknown";
const TURN_BASE: u64 = 1_800_000_000_000;

struct TurnFact {
    event: EventId,
    before: i64,
    after: i64,
    key: RecordKey,
}

/// Reader-side host double: real committed store, no background work.
struct FeedHost {
    reader: Arc<SqliteReader>,
    generation: Generation,
    fence: Arc<RecordFeedFence>,
}

impl AtlasHost for FeedHost {
    fn generation(&self) -> Generation {
        self.generation
    }
    fn records(&self) -> &Arc<RecordFeedFence> {
        &self.fence
    }
    fn checked_read_phase(&self) -> se_types::Result<ReadPhase> {
        let expected = self.generation;
        let phase = self.reader.read_phase().map_err(|e| store_error(&e))?;
        let result =
            phase
                .runtime_owner()
                .map_err(|e| store_error(&e))
                .and_then(|owner| match owner {
                    Read::Present { value } if value.generation == expected => Ok(()),
                    Read::Present { .. } => Err(SeError::invalid(
                        "execution generation",
                        "the same committed runtime owner generation",
                    )),
                    Read::Absent { checked } => Err(scope::unreadable(
                        "execution generation",
                        &format!("runtime owner absent: {checked}"),
                    )),
                    Read::Unreadable { source, reason, .. } => {
                        Err(scope::unreadable(&source, &reason))
                    }
                    Read::Unknown { what } => Err(scope::unreadable("execution generation", &what)),
                });
        match result {
            Ok(()) => Ok(phase),
            Err(error) => close_read(Err(error), phase.close()),
        }
    }
    fn run_background_owned(
        &self,
        _timeout: Duration,
        _work: BoxedWork,
    ) -> HostFuture<'_, Box<dyn Any + Send>> {
        Box::pin(async {
            Err(SeError::invalid(
                "Atlas host test double",
                "no background work in this test",
            ))
        })
    }
    fn run_owned(
        &self,
        _remaining: Duration,
        _work: BoxedWork,
    ) -> HostFuture<'_, Box<dyn Any + Send>> {
        Box::pin(async {
            Err(SeError::invalid(
                "Atlas host test double",
                "no foreground work in this test",
            ))
        })
    }
}

fn close_read<T>(
    result: se_types::Result<T>,
    closed: se_store::StoreResult<()>,
) -> se_types::Result<T> {
    match (result, closed) {
        (result, Ok(())) => result,
        (Ok(_), Err(error)) => Err(store_error(&error)),
        (Err(original), Err(error)) => Err(original.with_cause(error)),
    }
}

/// Record checks for one verified viewer, baked into the implementation.
struct ViewerRecords<'a> {
    reader: AtlasRecordReader<'a, SqliteSnapshot>,
    project: ProjectId,
    viewer: AtlasPrincipal,
}

impl RecordCheck for ViewerRecords<'_> {
    fn hit(
        &self,
        pointer: &RecordPointer,
        query: Option<&QueryText>,
    ) -> se_types::Result<Read<RecordHit>> {
        self.reader
            .read(&self.project, &self.viewer, pointer, query)
    }
}

fn transcript_text(
    agent: &AgentId,
    session: &SessionId,
    source: RecordId,
    cwd: &str,
    length: u64,
) -> Result<String, Box<dyn Error>> {
    let observation = Observation {
        schema: SCHEMA.to_owned(),
        session: session.clone(),
        agent: agent.clone(),
        provider: Provider::Claude,
        source,
        position: Position { offset: 0, length },
        native: NativeIdentity::ClaudeCall {
            tool_use_id: "toolu_public".into(),
        },
        phase: Phase::Completed,
        tool: ToolName::Known("Edit".into()),
        target: Target::Paths(vec![ObservedPath {
            spelling: SERVICE_FILE.to_owned(),
            cwd: Some(cwd.to_owned()),
            content_revision: None,
        }]),
        outcome: Outcome::Succeeded,
    };
    let mut record = Record::new("captured-tool", None);
    record.position = observation.position.clone();
    record.captured_tool = Some(observation);
    Ok(serde_json::to_string(&record)?)
}

fn expected_tool_key(
    session: &SessionId,
    source: RecordId,
    length: u64,
) -> Result<RecordKey, Box<dyn Error>> {
    let native = NativeIdentity::ClaudeCall {
        tool_use_id: "toolu_public".into(),
    };
    let position = Position { offset: 0, length };
    let identity = (
        session,
        source,
        Provider::Claude,
        &native,
        Phase::Completed,
        &position,
    );
    let digest = Sha256::digest(serde_json::to_vec(&identity)?);
    Ok(RecordKey::new(format!("tool:{digest:x}"))?)
}

fn now_ms() -> Result<i64, Box<dyn Error>> {
    let elapsed = SystemTime::now().duration_since(UNIX_EPOCH)?;
    i64::try_from(elapsed.as_millis()).map_err(|error| error.to_string().into())
}

fn stage_capture(
    f: &Fixture,
    session: &SessionId,
    source: RecordId,
    turn: RecordId,
    worktree: &Path,
) -> Result<TurnFact, Box<dyn Error>> {
    let (mut direct, lease) = f.direct()?;
    direct.append(
        f.batch(
            f.owner_project(),
            Some(request("session-lifecycle")?),
            vec![
                capture_fixture::prepared(f, session, &f.a),
                capture_fixture::activated(session)?,
                capture_fixture::source(source, session, b"first", Expected::Absent),
            ],
        )?,
        &*lease,
    )?;
    let cwd = worktree.to_string_lossy().into_owned();
    let mut text = transcript_text(&f.a, session, source, &cwd, 1)?;
    for _ in 0..32 {
        let candidate = transcript_text(&f.a, session, source, &cwd, text.len() as u64)?;
        if candidate == text {
            break;
        }
        text = candidate;
    }
    let length = text.len() as u64;
    if transcript_text(&f.a, session, source, &cwd, length)? != text {
        return Err("the transcript length did not converge".into());
    }
    fs::write(f.home.join("transcript.jsonl"), text.as_bytes())?;
    let mut admission = f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone()));
    admission.session = Some(session.clone());
    let mut batch = f.batch(
        admission,
        None,
        vec![
            EventBody::SessionTurn {
                turn,
                agent: f.a.clone(),
                session: session.clone(),
                provider: Provider::Claude,
                vendor_ref: "se.notice.v1/captured-tool".into(),
                role: Role::System,
                text: InputText::Inline(text.clone()),
                evidence: SourceEvidence {
                    path: Some(NativePath::from_local(f.home.join("transcript.jsonl"))?),
                    incarnation: b"first".to_vec(),
                    offset: 0,
                    length,
                    sha256: Some(Sha256::digest(text.as_bytes()).into()),
                },
            },
            EventBody::CaptureProgress {
                source,
                expected: revision(1)?,
                incarnation: b"first".to_vec(),
                old_offset: 0,
                new_offset: length,
                last_turn: turn,
                replay_evidence: None,
            },
        ],
    )?;
    for event in &mut batch.events {
        event.header.session = Some(session.clone());
    }
    let event = batch.events[0].header.event.clone();
    let before = now_ms()?;
    direct.append(batch, &*lease)?;
    let after = now_ms()?;
    direct.close()?;
    drop(lease);
    Ok(TurnFact {
        event,
        before,
        after,
        key: expected_tool_key(session, source, length)?,
    })
}

fn edit_hits(
    f: &Fixture,
    host: &FeedHost,
    root: &Root,
    agent: &AgentId,
) -> Result<Vec<SearchHit>, Box<dyn Error>> {
    let admission = f.admission(
        Scope::Project(f.project.clone()),
        Actor::Agent(agent.clone()),
    );
    let phase = host.checked_read_phase()?;
    let mut snapshot = phase
        .into_snapshot(read_scope(&admission))
        .map_err(|e| store_error(&e))?;
    let reader = AtlasRecordReader::new(&mut snapshot, &admission);
    let check = ViewerRecords {
        reader,
        project: f.project.clone(),
        viewer: AtlasPrincipal::Agent(agent.clone()),
    };
    let query = support::find_query(
        SearchKind::Edit,
        "captured",
        support::budget(10, 65_536)?,
        None,
    )?;
    let answer = root.find(&query, &check)?;
    Ok(support::present(answer.data)?.page.items().to_vec())
}

fn assert_edit_visible(f: &Fixture, host: &FeedHost, root: &Root, fact: &TurnFact) -> Check {
    let hits = edit_hits(f, host, root, &f.a)?;
    if hits.len() != 1 {
        return Err(format!(
            "expected exactly one edit record for the author, found {}",
            hits.len()
        )
        .into());
    }
    let HitTarget::Record(hit) = &hits[0].target else {
        return Err("the author's edit search must return the record target".into());
    };
    if hit.pointer.key.as_str() != fact.key.as_str() {
        return Err("the edit record key must bind to the captured tool identity".into());
    }
    if hit.pointer.kind != RecordKind::Edit {
        return Err("the edit record kind must be Edit".into());
    }
    if hit.pointer.source_event != fact.event {
        return Err("the edit record must cite its committed turn event".into());
    }
    let author = AtlasActor {
        principal: AtlasPrincipal::Agent(f.a.clone()),
        name: f.a.to_string(),
    };
    if hit.actor != Some(author) {
        return Err("the edit record must attribute the capturing agent".into());
    }
    if !(fact.before..=fact.after).contains(&hit.occurred_unix_ms) {
        return Err("the edit record time must fall inside the observed append window".into());
    }
    if hit.line != DESCRIPTION {
        return Err("the edit record line must be the canonical capture description".into());
    }
    if hit.body_truncated {
        return Err("the edit record body must not be truncated".into());
    }
    Ok(())
}

fn assert_edit_hidden(f: &Fixture, host: &FeedHost, root: &Root) -> Check {
    let hits = edit_hits(f, host, root, &f.b)?;
    if !hits.is_empty() {
        return Err(format!(
            "the edit record must stay hidden from another agent, found {}",
            hits.len()
        )
        .into());
    }
    Ok(())
}

fn assert_sql(state_dir: &Path, fact: &TurnFact, agent: &AgentId) -> Check {
    let db = support::epoch_db_path(state_dir)?;
    let conn = rusqlite::Connection::open(&db)?;
    assert_sql_record(&conn, fact, agent)?;
    assert_sql_touch(&conn, fact, agent)
}

fn assert_sql_record(conn: &rusqlite::Connection, fact: &TurnFact, agent: &AgentId) -> Check {
    let count: i64 = conn.query_row(
        "SELECT count(*) FROM records WHERE record_id = ?1",
        rusqlite::params![fact.key.as_str()],
        |row| row.get(0),
    )?;
    if count != 1 {
        return Err(format!("expected exactly one committed records row, found {count}").into());
    }
    let (kind, visibility, source_event, actor, audience) = conn.query_row(
        "SELECT kind, visibility, source_event, actor, audience FROM records WHERE record_id = ?1",
        rusqlite::params![fact.key.as_str()],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<Vec<u8>>>(4)?,
            ))
        },
    )?;
    if kind != "edit" {
        return Err(format!("records row kind must be edit, got {kind:?}").into());
    }
    if visibility != "restricted" {
        return Err(
            format!("records row visibility must be restricted, got {visibility:?}").into(),
        );
    }
    if source_event != fact.event.as_str() {
        return Err("records row must cite the committed turn event".into());
    }
    let actor = actor.as_deref().unwrap_or_default();
    if !actor.contains(agent.as_str()) {
        return Err("records row actor must attribute the capturing agent".into());
    }
    let audience = audience
        .as_deref()
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .unwrap_or_default();
    if !audience.contains(agent.as_str()) {
        return Err("records row audience must include the capturing agent".into());
    }
    Ok(())
}

fn assert_sql_touch(conn: &rusqlite::Connection, fact: &TurnFact, agent: &AgentId) -> Check {
    let count: i64 = conn.query_row(
        "SELECT count(*) FROM touches t JOIN records r ON r.id = t.source_record WHERE r.record_id = ?1",
        rusqlite::params![fact.key.as_str()],
        |row| row.get(0),
    )?;
    if count != 1 {
        return Err(format!(
            "expected exactly one touches row for the edit file mention, found {count}"
        )
        .into());
    }
    let (target_kind, touch_kind, touch_actor, restricted) = conn.query_row(
        "SELECT t.target_kind, t.touch_kind, t.actor, t.restricted_record FROM touches t JOIN records r ON r.id = t.source_record WHERE r.record_id = ?1",
        rusqlite::params![fact.key.as_str()],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<i64>>(3)?,
            ))
        },
    )?;
    if target_kind != "file" {
        return Err(format!(
            "the file mention must resolve to an indexed file, got {target_kind:?}"
        )
        .into());
    }
    if touch_kind != "tool_edit" {
        return Err(format!("the edit touch must be a tool touch, got {touch_kind:?}").into());
    }
    let touch_actor = touch_actor.as_deref().unwrap_or_default();
    if !touch_actor.contains(agent.as_str()) {
        return Err("the touch must attribute the capturing agent".into());
    }
    if restricted.is_none() {
        return Err("the restricted edit touch must point at its record".into());
    }
    Ok(())
}

#[test]
fn captured_provider_edit_reaches_v5_activity_and_only_its_author() -> Check {
    let f = Fixture::new()?;
    let worktree = f.home.join("worktree");
    fs::create_dir_all(worktree.join("src"))?;
    fs::write(worktree.join(SERVICE_FILE), SERVICE_SOURCE)?;
    let worktree = fs::canonicalize(worktree)?;
    let session = SessionId::from_parts(TURN_BASE + 1, [1; 10])?;
    let source = RecordId::from_parts(TURN_BASE + 2, [2; 10])?;
    let turn = RecordId::from_parts(TURN_BASE + 3, [3; 10])?;
    let fact = stage_capture(&f, &session, source, turn, &worktree)?;
    drop(host_fixture::host_from_existing(&f)?);
    let reader = Arc::new(support::present(SqliteFactory::open_reader_with_capacity(
        &f.options,
        NonZeroU32::new(4).ok_or("reader capacity")?,
    )?)?);
    let state_dir = f.home.join("atlas");
    let spec = RootSpec {
        project: f.project.clone(),
        root: support::root_id(9)?,
        source: worktree.clone(),
        directory: state_dir.clone(),
    };
    let root = Root::start(spec.clone())?;
    support::wait_current(&root, support::SETTLE_TIMEOUT)?;
    let feed_host = FeedHost {
        reader,
        generation: Generation::new(1)?,
        fence: Arc::new(RecordFeedFence::default()),
    };
    support::wait_until(
        support::SETTLE_TIMEOUT,
        "record feed current",
        || match chunk(&feed_host, &f.owner, &root) {
            Ok(Fed::Current) => Ok(Some(())),
            Ok(Fed::More | Fed::Waiting) => Ok(None),
            Err(error) => Err(format!("record chunk: {error}").into()),
        },
    )?;
    let Some(epoch) = root.summary()?.epoch else {
        return Err("the settled root must report its cache epoch".into());
    };
    let fence_scope = RecordFeedScope {
        project: f.project.clone(),
        root: spec.root.clone(),
        epoch,
    };
    let ticket = feed_host.fence.ticket()?;
    if !feed_host.fence.is_current(&fence_scope, ticket)? {
        return Err("the fed worktree must be certified current for the captured fence".into());
    }
    assert_edit_visible(&f, &feed_host, &root, &fact)?;
    assert_edit_hidden(&f, &feed_host, &root)?;
    assert_sql(&state_dir, &fact, &f.a)?;
    root.stop(support::STOP_TIMEOUT)?;
    Ok(())
}
