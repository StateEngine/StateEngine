type ResumeRow = (
    Option<u64>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
    u64,
    u64,
    u64,
);
mod capture;
mod continuity;
mod control;
mod cursor;
mod decision;
mod decision_heads;
mod message;
mod message_count;
mod page;
mod project;
mod query;
mod runtime;
use crate::{codec, connection, error::*, identity::*, open::SqliteReader, *};
use rusqlite::{Connection, OptionalExtension};
use se_types::{
    AgentId, Cursor, EventId, Omission, OmissionReason, Page, ProjectId, Read, Sequence, Source,
    StopReason, Window, WindowFields,
};
use se_types::{DecisionId, LifecycleId, SessionId};
use std::{marker::PhantomData, rc::Rc, time::Instant};
pub struct SqliteSnapshot {
    pub(crate) db: Connection,
    info: StoreInfo,
    scope: ReadScope,
    path: std::path::PathBuf,
    _slot: crate::read_slots::ReadSlot,
    _local: PhantomData<Rc<()>>,
}
impl SqliteSnapshot {
    pub(crate) fn open(reader: &SqliteReader, scope: ReadScope) -> StoreResult<Self> {
        reader.read_phase()?.into_snapshot(scope)
    }
    pub(crate) fn from_phase(phase: ReadPhase, scope: ReadScope) -> StoreResult<Self> {
        if phase.info.state != StoreState::Ready {
            return Err(fail(StoreErrorCode::NotReady, "store is in maintenance"));
        }
        Ok(Self {
            db: phase.db,
            info: phase.info,
            scope,
            path: phase.path,
            _slot: phase.slot,
            _local: phase.local,
        })
    }
    /// Narrow one owner Registry read pin after CLI project selection. This
    /// changes no principal, visibility, generation or snapshot boundary.
    pub fn select_project(&mut self, project: ProjectId) -> StoreResult<()> {
        if self.scope.admission.scope == Scope::Project(project.clone()) {
            return Ok(());
        }
        if !matches!(self.scope.admission.scope, Scope::Registry)
            || !matches!(self.scope.visibility, Visibility::Owner)
            || !matches!(self.scope.admission.actor, Actor::Human(_))
            || self.scope.admission.session.is_some()
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "only an owner Registry pin can narrow to a selected project",
            ));
        }
        self.scope.admission.scope = Scope::Project(project);
        Ok(())
    }
    fn read_sql(&self, error: rusqlite::Error) -> Box<StoreError> {
        let interrupted =
            error.sqlite_error_code() == Some(rusqlite::ErrorCode::OperationInterrupted);
        let mut mapped = sql(error);
        if interrupted {
            mapped.code = StoreErrorCode::ReadIncomplete;
            mapped.cause = "SQLite read deadline/step budget exhausted".into();
        }
        context(mapped, &self.path, StoreIoStage::ReadSnapshot)
    }
    fn event_seq(&self, id: &EventId) -> StoreResult<Option<i64>> {
        let s = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let key = key(&self.db, "event", id.as_str(), &s, false)?;
        let p = match self.scope.admission.scope {
            Scope::Registry => None,
            _ => Some(connection::project_id(
                &self.db,
                &self.scope.admission.scope,
                false,
            )?),
        };
        let row: Option<(i64, Option<Vec<u8>>)> = self
            .db
            .query_row(
                "SELECT seq,project_id FROM events WHERE event_id=?",
                [key],
                |r| {
                    Ok((
                        crate::sql_value::value(r, 0)?,
                        crate::sql_value::value(r, 1)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| self.read_sql(error))?;
        match row {
            Some((_, project)) if project != p => Err(fail(
                StoreErrorCode::ScopeMismatch,
                "event is outside admitted scope",
            )),
            Some((seq, _)) => Ok(Some(seq)),
            None => {
                // Legacy wire IDs use scope-specific storage keys. An alias in another
                // scope proves exclusion only when it names a retained event.
                let excluded = canonical(id.as_str()).is_none() && self.db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM identities i JOIN events e ON e.event_id=i.storage_key WHERE i.kind='event' AND i.wire_id=?)",
                    [id.as_str()],
                    |r| crate::sql_value::value::<bool>(r, 0),
                ).map_err(|error| self.read_sql(error))?;
                if excluded {
                    return Err(fail(
                        StoreErrorCode::ScopeMismatch,
                        "event is outside admitted scope",
                    ));
                }
                Ok(None)
            }
        }
    }

    fn visible(&self, e: &StoredEvent) -> StoreResult<bool> {
        Ok(match &self.scope.visibility {
            Visibility::Owner | Visibility::SharedProject(_) => true,
            Visibility::SelfOnly(a) => {
                let who = Actor::Agent(a.clone());
                if e.header.actor == who {
                    return Ok(true);
                }
                if let Some(about) = self.agent_fact(&e.body, a)? {
                    return Ok(about);
                }
                match &e.body {
                    EventBody::MessageSent { recipient, .. } => *recipient == who,
                    EventBody::WorkingStateSet { agent, .. }
                    | EventBody::SessionTurn { agent, .. } => agent == a,
                    EventBody::CaptureSource { session, .. }
                    | EventBody::CaptureFailed { session, .. }
                    | EventBody::CaptureSuppressed { session, .. } => {
                        self.session_visible(session, a)?
                    }
                    EventBody::CaptureProgress { source, .. } => self.source_visible(source, a)?,
                    EventBody::EffectRequested { principal, .. } => {
                        principal.as_ref() == Some(&who)
                    }
                    EventBody::EffectOffered { principal, .. } => *principal == who,
                    EventBody::EffectSettled { effect, .. } => self.effect_visible(effect, a)?,
                    EventBody::CursorRecorded { cursor } => cursor.agent == *a,
                    EventBody::CursorAcknowledged { cursor, .. } => {
                        self.cursor_visible(cursor, a)?
                    }
                    _ => false,
                }
            }
        })
    }
    /// Whether a principal, session or process fact concerns `agent`; None for
    /// every other kind. The one allow-list shared by self visibility and the
    /// creator-control port.
    fn agent_fact(
        &self,
        body: &EventBody<StoredText>,
        agent: &AgentId,
    ) -> StoreResult<Option<bool>> {
        let who = Actor::Agent(agent.clone());
        Ok(Some(match body {
            EventBody::PrincipalRegistered { principal, .. } => *principal == who,
            EventBody::SessionPrepared { agent: owner, .. } => owner == agent,
            EventBody::SessionActivated { session, .. }
            | EventBody::SessionEnded { session, .. }
            | EventBody::SessionRevoked { session, .. } => self.session_of(session, agent)?,
            EventBody::ProcessRegistered { identity, .. }
            | EventBody::ProcessTransition { identity, .. } => identity.principal == who,
            _ => return Ok(None),
        }))
    }
    fn record(&self, seq: i64) -> StoreResult<StoredEvent> {
        let e = load_event(&self.db, seq, &self.info)
            .map_err(|error| context(error, &self.path, StoreIoStage::ReadSnapshot))?;
        if matches!(
            e.body,
            EventBody::RuntimeOwnerEstablished { .. } | EventBody::RuntimeHandoverRecorded { .. }
        ) {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "runtime ownership facts are private maintenance data",
            ));
        }
        if !self.visible(&e)? {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "event is outside admitted visibility",
            ));
        }
        Ok(e)
    }
    fn project_metadata(&self, seq: i64) -> StoreResult<StoredEvent> {
        if !matches!(self.scope.visibility, Visibility::SelfOnly(_)) {
            return self.record(seq);
        }
        let event = load_event(&self.db, seq, &self.info)
            .map_err(|error| context(error, &self.path, StoreIoStage::ReadSnapshot))?;
        let project = match &event.body {
            EventBody::ProjectRegistered { project, .. }
            | EventBody::ProjectUpdated { project, .. }
            | EventBody::ProjectRemoved { project, .. } => project,
            _ => {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "public project metadata has a different event kind",
                ));
            }
        };
        if self.scope.admission.scope != Scope::Project(project.clone()) {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "public project metadata is outside the admitted project",
            ));
        }
        Ok(event)
    }
    fn principal_metadata(&self, seq: i64) -> StoreResult<StoredEvent> {
        let event = load_event(&self.db, seq, &self.info)
            .map_err(|error| context(error, &self.path, StoreIoStage::ReadSnapshot))?;
        if event.header.scope != self.scope.admission.scope
            || !matches!(
                event.body,
                EventBody::PrincipalRegistered { .. } | EventBody::PrincipalRenamed { .. }
            )
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "public principal metadata is outside the admitted project or kind",
            ));
        }
        Ok(event)
    }
    fn absent<T>(&self, what: &str) -> Read<T> {
        Read::Absent {
            checked: format!(
                "{what}; store {} incarnation {} finite snapshot",
                self.info.id, self.info.incarnation
            ),
        }
    }
    fn head(
        &self,
        table: &str,
        filter: &str,
        keys: &[&dyn rusqlite::ToSql],
        original: Option<&str>,
    ) -> StoreResult<Read<ProjectionRecord>> {
        self.head_with(table, filter, keys, original, &|seq| {
            if table == "principals" {
                self.principal_metadata(seq)
            } else if table == "projects" {
                self.project_metadata(seq)
            } else {
                self.record(seq)
            }
        })
    }
    /// One current head plus its original event, each loaded by `load`, which
    /// owns the visibility decision for that event.
    fn head_with(
        &self,
        table: &str,
        filter: &str,
        keys: &[&dyn rusqlite::ToSql],
        original: Option<&str>,
        load: &dyn Fn(i64) -> StoreResult<StoredEvent>,
    ) -> StoreResult<Read<ProjectionRecord>> {
        let row: Option<(u64, i64, Option<i64>)> = self
            .db
            .query_row(
                &format!(
                    "SELECT revision,last_seq,{} FROM {table} WHERE {filter}",
                    original.unwrap_or("NULL")
                ),
                keys,
                |r| {
                    Ok((
                        crate::sql_value::value(r, 0)?,
                        crate::sql_value::value(r, 1)?,
                        crate::sql_value::value(r, 2)?,
                    ))
                },
            )
            .optional()
            .map_err(|error| self.read_sql(error))?;
        match row {
            None => Ok(self.absent(table)),
            Some((revision, seq, first)) => Ok(Read::Present {
                value: ProjectionRecord {
                    revision: codec::revision(revision)?,
                    current: load(seq)?,
                    original: first
                        .filter(|s| *s != seq)
                        .map(|s| load(s).map(Box::new))
                        .transpose()?,
                },
            }),
        }
    }
    fn project_bytes(&self) -> StoreResult<Vec<u8>> {
        connection::project_id(&self.db, &self.scope.admission.scope, false)
    }
    fn agent_bytes(&self, a: &AgentId) -> StoreResult<Vec<u8>> {
        if let Visibility::SelfOnly(own) = &self.scope.visibility
            && own != a
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "private agent read refused",
            ));
        }
        key(
            &self.db,
            "agent",
            a.as_str(),
            &scope_key(&self.db, &self.scope.admission.scope, false)?,
            false,
        )
    }
    fn message_at(
        &self,
        sent: i64,
        revision: u64,
        delivered: Option<u64>,
        read: Option<u64>,
        dismissed: Option<u64>,
    ) -> StoreResult<MessageRecord> {
        let e = self.record(sent)?;
        let EventBody::MessageSent {
            message,
            recipient,
            kind,
            body,
            refs,
            reply_to,
        } = e.body
        else {
            return Err(invalid("message head points to another event kind"));
        };
        let pos = |s| StorePosition::new_internal(self.info.id.clone(), self.info.incarnation, s);
        Ok(MessageRecord {
            message,
            event: e.header.event,
            revision: codec::revision(revision)?,
            sent: e.position,
            sender: e.header.actor,
            recipient,
            kind,
            body,
            refs,
            reply_to,
            delivered: delivered.map(pos).transpose()?,
            read: read.map(pos).transpose()?,
            dismissed: dismissed.map(pos).transpose()?,
            body_complete: true,
        })
    }
}
impl Drop for SqliteSnapshot {
    fn drop(&mut self) {
        let _ = self.db.execute_batch("ROLLBACK");
    }
}
pub struct LegacyRegistry<'a> {
    snapshot: &'a SqliteSnapshot,
}
impl se_types::LegacyIdRegistry for LegacyRegistry<'_> {
    fn contains(&self, kind: se_types::IdKind, text: &str) -> se_types::Result<bool> {
        let scope = scope_key(
            &self.snapshot.db,
            &self.snapshot.scope.admission.scope,
            false,
        )
        .map_err(|e| se_types::SeError::invalid("legacy registry", &e.cause))?;
        let kind = match kind {
            se_types::IdKind::AgentId => "agent",
            se_types::IdKind::HumanId => "human",
            se_types::IdKind::ProjectId => "project",
            se_types::IdKind::MessageId => "message",
            se_types::IdKind::DecisionId => "decision",
            se_types::IdKind::EventId => "event",
            se_types::IdKind::SessionId => "session",
            _ => return Ok(false),
        };
        self.snapshot.db.query_row("SELECT EXISTS(SELECT 1 FROM identities WHERE kind=? AND wire_id=? AND scope_key=? AND encoding='registered-exception')",rusqlite::params![kind,text,scope],|r|crate::sql_value::value(r,0)).map_err(|e|se_types::SeError::invalid("legacy registry",&e.to_string()))
    }
}
impl Snapshot for SqliteSnapshot {
    type LegacyRegistry<'a> = LegacyRegistry<'a>;
    fn legacy_registry(&self) -> StoreResult<Self::LegacyRegistry<'_>> {
        Ok(LegacyRegistry { snapshot: self })
    }
    fn info(&self) -> StoreInfo {
        self.info.clone()
    }
    fn position_cursor(
        &self,
        position: &StorePosition,
        purpose: PositionPurpose,
    ) -> StoreResult<Cursor> {
        let head = self
            .info
            .head
            .as_ref()
            .map(StorePosition::sequence)
            .unwrap_or(0);
        if !position.belongs(&self.info) || position.sequence() > head {
            return Err(fail(
                StoreErrorCode::CursorStale,
                "position is outside this store/incarnation/snapshot",
            ));
        }
        if position.sequence() > 0 {
            let e = self.record(position.sequence() as i64)?;
            if e.header.scope != self.scope.admission.scope {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "position is outside admitted scope",
                ));
            }
        }
        self.cursor(
            &self.position_binding(purpose)?,
            position.sequence(),
            position.sequence(),
        )
    }
    fn cursor_position(
        &self,
        cursor: &Cursor,
        purpose: PositionPurpose,
    ) -> StoreResult<StorePosition> {
        self.read_cursor_position(cursor, purpose)
    }
    fn event(&mut self, id: EventId) -> StoreResult<Read<StoredEvent>> {
        match self.event_seq(&id)? {
            Some(seq) => Ok(Read::Present {
                value: self.record(seq)?,
            }),
            None => Ok(self.absent("event ID")),
        }
    }
    fn project(&mut self, id: ProjectId) -> StoreResult<Read<ProjectionRecord>> {
        if self.scope.admission.scope != Scope::Registry
            && self.scope.admission.scope != Scope::Project(id.clone())
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "project differs from admission",
            ));
        }
        let p = key(&self.db, "project", id.as_str(), &[0], false)?;
        self.head("projects", "project_id=?", &[&p], Some("first_seq"))
    }
    fn principal(&mut self, id: Actor) -> StoreResult<Read<ProjectionRecord>> {
        if self.scope.admission.scope == Scope::Registry {
            if !matches!(self.scope.visibility, Visibility::Owner) || !matches!(id, Actor::Human(_))
            {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "registry principal read requires admitted owner",
                ));
            }
            let a = key(&self.db, "human", id.wire(), &[0], false)?;
            return self.head("owners", "human_id=?", &[&a], Some("first_seq"));
        }
        let p = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let a = key(
            &self.db,
            id.kind(),
            id.wire(),
            if id.kind() == "human" { &[0] } else { &scope },
            false,
        )?;
        self.head(
            "principals",
            "project_id=? AND principal_id=?",
            &[&p, &a],
            Some("first_seq"),
        )
    }
    fn profile(&mut self, agent: AgentId) -> StoreResult<Read<ProjectionRecord>> {
        let p = self.project_bytes()?;
        let a = self.agent_bytes(&agent)?;
        self.head("profiles", "project_id=? AND agent_id=?", &[&p, &a], None)
    }
    fn grant(&mut self, principal: Actor, grant: GrantKey) -> StoreResult<Read<ProjectionRecord>> {
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let a = key(
            &self.db,
            principal.kind(),
            principal.wire(),
            if principal.kind() == "human" {
                &[0]
            } else {
                &scope
            },
            false,
        )?;
        self.head(
            "grants",
            "scope_key=? AND principal_id=? AND grant_key=?",
            &[&scope, &a, &codec::encode(&grant)?],
            None,
        )
    }
    fn working_state(&mut self, agent: AgentId) -> StoreResult<Read<ProjectionRecord>> {
        let p = self.project_bytes()?;
        let a = self.agent_bytes(&agent)?;
        self.head(
            "working_state",
            "project_id=? AND agent_id=?",
            &[&p, &a],
            None,
        )
    }
    fn message(&mut self, id: se_types::MessageId) -> StoreResult<Read<MessageRecord>> {
        let p = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let m = key(&self.db, "message", id.as_str(), &scope, false)?;
        let row:Option<message::MarkRow>=self.db.query_row("SELECT d.sent_seq,d.revision,m.delivered_seq,m.read_seq,m.dismissed_seq FROM messages d JOIN marks m ON m.message_seq=d.sent_seq WHERE d.project_id=? AND d.message_id=?",crate::sql_value::sql_params![p,m],|r|Ok((crate::sql_value::value(r,0)?,crate::sql_value::value(r,1)?,crate::sql_value::value(r,2)?,crate::sql_value::value(r,3)?,crate::sql_value::value(r,4)?))).optional().map_err(|error| self.read_sql(error))?;
        match row {
            None => Ok(self.absent("message ID")),
            Some((s, v, d, r, x)) => Ok(Read::Present {
                value: self.message_at(s, v, d, r, x)?,
            }),
        }
    }
    fn messages(
        &mut self,
        query: MessageQuery,
        budget: ReadBudget,
    ) -> StoreResult<Page<MessageRecord>> {
        self.read_messages(query, budget)
    }
    fn message_count(&mut self, query: MessageQuery) -> StoreResult<u64> {
        self.count_messages(query)
    }
    fn operation_receipt(
        &mut self,
        actor: Actor,
        request: se_types::IdempotencyKey,
    ) -> StoreResult<Read<CommitReceipt>> {
        if actor != self.scope.admission.actor
            && !matches!(self.scope.visibility, Visibility::Owner)
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "request receipt belongs to another actor",
            ));
        }
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let a = key(
            &self.db,
            actor.kind(),
            actor.wire(),
            if actor.kind() == "human" {
                &[0]
            } else {
                &scope
            },
            false,
        )?;
        let op:Option<Vec<u8>>=self.db.query_row("SELECT operation_id FROM operations WHERE scope_key=? AND actor_id=? AND request_key=? AND erased=0",crate::sql_value::sql_params![scope,a,request.as_str()],|r|crate::sql_value::value(r,0)).optional().map_err(|error| self.read_sql(error))?;
        match op {
            Some(op) => Ok(Read::Present {
                value: crate::transaction::receipt(&self.db, &op, &self.info, Some(request))?,
            }),
            None => Ok(self.absent("operation request key")),
        }
    }
    fn resume_head(&mut self, principal: Actor) -> StoreResult<Read<ResumeHead>> {
        if principal != self.scope.admission.actor
            && !matches!(self.scope.visibility, Visibility::Owner)
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "resume belongs to another principal",
            ));
        }
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let a = key(
            &self.db,
            principal.kind(),
            principal.wire(),
            if principal.kind() == "human" {
                &[0]
            } else {
                &scope
            },
            false,
        )?;
        let p = self.project_bytes()?;
        let row:Option<ResumeRow>=self.db.query_row("SELECT last_turn_seq,last_working_state_seq,last_cursor_seq,last_session_seq,unread_count,pending_effect_count,last_seq FROM resume_heads WHERE project_id=? AND principal_id=?",crate::sql_value::sql_params![p,a],|r|Ok((crate::sql_value::value(r,0)?,crate::sql_value::value(r,1)?,crate::sql_value::value(r,2)?,crate::sql_value::value(r,3)?,crate::sql_value::value(r,4)?,crate::sql_value::value(r,5)?,crate::sql_value::value(r,6)?))).optional().map_err(|error| self.read_sql(error))?;
        let pos = |s| StorePosition::new_internal(self.info.id.clone(), self.info.incarnation, s);
        match row {
            None => Ok(self.absent("resume head")),
            Some((t, w, c, s, unread, pending, last)) => Ok(Read::Present {
                value: ResumeHead {
                    principal,
                    turn: t.map(pos).transpose()?,
                    working_state: w.map(pos).transpose()?,
                    cursor: c.map(pos).transpose()?,
                    session: s.map(pos).transpose()?,
                    unread,
                    pending_effects: pending,
                    through: pos(last)?,
                },
            }),
        }
    }
    fn close(self) -> StoreResult<()> {
        self.db
            .execute_batch("ROLLBACK")
            .map_err(|error| self.read_sql(error))
    }
    fn history(
        &mut self,
        _query: HistoryQuery,
        _budget: ReadBudget,
    ) -> StoreResult<Page<StoredEvent>> {
        self.read_history(_query, _budget)
    }
    fn search(&mut self, _query: SearchQuery, _budget: ReadBudget) -> StoreResult<Page<SearchHit>> {
        later("search")
    }
    fn projects(&mut self, _budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        if !matches!(self.scope.visibility, Visibility::Owner) {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "project enumeration is owner-only",
            ));
        }
        self.list_heads("projects", "first_seq", "state='active'", vec![], _budget)
    }
    fn removed_projects(
        &mut self,
        query: RemovedProjectQuery,
        budget: ReadBudget,
    ) -> StoreResult<Page<ProjectionRecord>> {
        self.read_removed_projects(query, budget)
    }
    fn principals(&mut self, _budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        if self.scope.admission.scope == Scope::Registry {
            if !matches!(self.scope.visibility, Visibility::Owner) {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "owner registry enumeration refused",
                ));
            }
            return self.list_heads("owners", "first_seq", "1=1", vec![], _budget);
        }
        let p = self.project_bytes()?;
        self.list_heads(
            "principals",
            "first_seq",
            "project_id=?",
            vec![rusqlite::types::Value::Blob(p)],
            _budget,
        )
    }
    fn session(&mut self, _id: SessionId) -> StoreResult<Read<ProjectionRecord>> {
        self.read_session(_id)
    }
    fn latest_session(&mut self, agent: AgentId) -> StoreResult<Read<ProjectionRecord>> {
        let p = self.project_bytes()?;
        let a = self.agent_bytes(&agent)?;
        self.head(
            "sessions",
            "project_id=? AND agent_id=? AND first_seq=(SELECT MAX(first_seq) FROM sessions WHERE project_id=? AND agent_id=?)",
            &[&p, &a, &p, &a],
            Some("first_seq"),
        )
    }
    fn sessions(&mut self, _budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        let p = self.project_bytes()?;
        if let Visibility::SelfOnly(agent) = &self.scope.visibility {
            let a = self.agent_bytes(agent)?;
            self.list_heads(
                "sessions",
                "first_seq",
                "project_id=? AND agent_id=?",
                vec![
                    rusqlite::types::Value::Blob(p),
                    rusqlite::types::Value::Blob(a),
                ],
                _budget,
            )
        } else {
            self.list_heads(
                "sessions",
                "first_seq",
                "project_id=?",
                vec![rusqlite::types::Value::Blob(p)],
                _budget,
            )
        }
    }
    fn decision(&mut self, _id: DecisionId) -> StoreResult<Read<ProjectionRecord>> {
        let p = self.project_bytes()?;
        let s = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let d = key(&self.db, "decision", _id.as_str(), &s, false)?;
        self.head_with(
            "decisions",
            "project_id=? AND decision_id=?",
            &[&p, &d],
            Some("proposed_seq"),
            &|seq| self.decision_event(seq, &_id),
        )
    }
    fn decision_predecessor(&mut self, id: DecisionId) -> StoreResult<Read<DecisionId>> {
        self.read_decision_predecessor(id)
    }
    fn decision_transitions(
        &mut self,
        id: DecisionId,
        budget: ReadBudget,
    ) -> StoreResult<Read<Page<StoredEvent>>> {
        self.read_decision_transitions(id, budget, false)
    }
    fn decision_detail_transitions(
        &mut self,
        id: DecisionId,
        budget: ReadBudget,
    ) -> StoreResult<Read<Page<StoredEvent>>> {
        self.read_decision_transitions(id, budget, true)
    }
    fn decisions(
        &mut self,
        query: DecisionQuery,
        budget: ReadBudget,
    ) -> StoreResult<Page<ProjectionRecord>> {
        self.read_decision_heads(query, false, budget)
    }
    fn decision_rows(
        &mut self,
        query: DecisionQuery,
        budget: ReadBudget,
    ) -> StoreResult<Page<Read<ProjectionRecord>>> {
        self.read_decision_rows(query, false, budget)
    }
    fn turn(&mut self, id: RecordId) -> StoreResult<Read<StoredEvent>> {
        self.read_turn(id)
    }
    fn recent_turns(
        &mut self,
        agent: AgentId,
        since: Option<StorePosition>,
        budget: ReadBudget,
    ) -> StoreResult<Page<StoredEvent>> {
        self.read_recent_turns(agent, since, budget)
    }
    fn governing_decisions(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        self.read_governing_decisions(budget)
    }
    fn decision_count(&mut self, pending_only: bool) -> StoreResult<u64> {
        self.read_decision_count(pending_only)
    }
    fn turns(&mut self, _agent: AgentId, _budget: ReadBudget) -> StoreResult<Page<StoredEvent>> {
        self.read_turns(_agent, _budget)
    }
    fn capture_source(&mut self, _source: RecordId) -> StoreResult<Read<ProjectionRecord>> {
        self.read_capture_source(_source)
    }
    fn control_target(&mut self, target: AgentId) -> StoreResult<Read<ControlTarget>> {
        self.read_control_target(target)
    }
    fn process(&mut self, _id: LifecycleId) -> StoreResult<Read<ProjectionRecord>> {
        let p = self.project_bytes()?;
        let s = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let id = key(&self.db, "lifecycle", _id.as_str(), &s, false)?;
        self.head(
            "processes",
            "project_id=? AND process_id=?",
            &[&p, &id],
            Some("first_seq"),
        )
    }
    fn processes(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        self.read_processes(budget)
    }
    fn cursor(&mut self, agent: AgentId, purpose: String) -> StoreResult<Read<CursorHead>> {
        self.read_cursor(agent, purpose)
    }
    fn pending_effects(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        self.read_pending_effects(budget)
    }
    fn effect(&mut self, id: RecordId) -> StoreResult<Read<ProjectionRecord>> {
        self.read_effect(id)
    }
    fn integrations(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        self.read_integrations(budget)
    }
    fn import_progress(
        &mut self,
        _import: RecordId,
        _budget: ReadBudget,
    ) -> StoreResult<Page<ImportCheckpoint>> {
        later("import_progress")
    }
}

pub(crate) use crate::codec::event::load_event;
pub(crate) use cursor::window_end;
