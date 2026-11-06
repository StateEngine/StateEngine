type ResumeRow = (
    Option<u64>,
    Option<u64>,
    Option<u64>,
    Option<u64>,
    u64,
    u64,
    u64,
);
mod access;
mod atlas_resume;
mod capture;
mod channel;
mod continuity;
mod control;
mod cursor;
mod decision;
mod decision_heads;
mod grant;
mod history;
mod import;
mod mail;
mod mail_legacy;
mod message;
mod message_count;
mod notification;
mod page;
mod project;
mod query;
mod receipt;
mod runtime;
mod search;
mod selector;
mod transcript;
use crate::{codec, connection, error::*, identity::*, open::SqliteReader, *};
use rusqlite::{Connection, OptionalExtension};
use se_types::{
    AgentId, Cursor, EventId, Omission, OmissionReason, Page, ProjectId, Read, Sequence, Source,
    StopReason, Window, WindowFields,
};
use se_types::{DecisionId, LifecycleId, SessionId};
use std::{marker::PhantomData, rc::Rc, time::Instant};
// SQLite closes and rolls back on implicit drop. Only an explicit successful
// close may return a connection to its host pool.
pub struct SqliteSnapshot {
    pub(crate) db: Connection,
    recycle: Option<crate::read_phase_pool::Recycle>,
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
            recycle: phase.recycle,
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
}
pub struct LegacyRegistry<'a> {
    snapshot: &'a SqliteSnapshot,
}
impl se_types::LegacyIdRegistry for LegacyRegistry<'_> {
    fn resolve_alias(
        &self,
        kind: se_types::IdKind,
        alias: &str,
    ) -> se_types::Result<Option<String>> {
        if kind != se_types::IdKind::AgentId {
            return Ok(None);
        }
        let p = self
            .snapshot
            .project_bytes()
            .map_err(|e| se_types::SeError::invalid("imported alias scope", &e.cause))?;
        let scope = scope_key(
            &self.snapshot.db,
            &self.snapshot.scope.admission.scope,
            false,
        )
        .map_err(|e| se_types::SeError::invalid("imported alias scope", &e.cause))?;
        let id:Option<Vec<u8>>=self.snapshot.db.query_row("SELECT a.principal_id FROM aliases a JOIN events e ON e.seq=a.imported_seq JOIN principals p ON p.project_id=a.project_id AND p.principal_id=a.principal_id WHERE a.project_id=? AND a.alias=? AND p.principal_kind='agent' AND e.door='import'",rusqlite::params![p,alias],|r|r.get(0)).optional().map_err(|e|se_types::SeError::invalid("imported alias lookup",&e.to_string()))?;
        id.map(|id| {
            wire(&self.snapshot.db, "agent", &id, &scope)
                .map_err(|e| se_types::SeError::invalid("imported alias target", &e.cause))
        })
        .transpose()
    }
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
        if kind != "agent" {
            return Ok(false);
        }
        se_types::LegacyIdRegistry::contains(
            &crate::identity::StoredLegacyRegistry {
                db: &self.snapshot.db,
                scope: &scope,
            },
            se_types::IdKind::AgentId,
            text,
        )
    }
}
impl Snapshot for SqliteSnapshot {
    type LegacyRegistry<'a> = LegacyRegistry<'a>;
    fn legacy_registry(&self) -> StoreResult<Self::LegacyRegistry<'_>> {
        Ok(LegacyRegistry { snapshot: self })
    }
    fn channel_reply_route(
        &mut self,
        message: &se_types::MessageId,
    ) -> StoreResult<Option<crate::channel::ReplyRoute>> {
        self.read_channel_route(message)
    }
    fn channel_active(&mut self) -> StoreResult<Vec<crate::channel::Connection>> {
        self.read_active_channels()
    }
    fn channel_update_handled(
        &mut self,
        id: &crate::channel::ChannelId,
        update: i64,
    ) -> StoreResult<bool> {
        self.read_update_handled(id, update)
    }
    fn channel_version(&mut self) -> StoreResult<crate::channel::Version> {
        self.read_channel_version()
    }
    fn channel_connection(
        &mut self,
        id: &crate::channel::ChannelId,
    ) -> StoreResult<Read<crate::channel::Connection>> {
        self.read_channel(id)
    }
    fn channel_connections(
        &mut self,
        after: u64,
    ) -> StoreResult<crate::channel::ChannelRows<crate::channel::Connection>> {
        self.read_channels(after)
    }
    fn channel_receipt(
        &mut self,
        id: &crate::channel::ChannelId,
        receipt: &crate::channel::ReceiptId,
    ) -> StoreResult<Read<crate::channel::SavedUpdate>> {
        self.read_saved_receipt(id, receipt)
    }
    fn channel_saved(
        &mut self,
        id: &crate::channel::ChannelId,
        after: u64,
    ) -> StoreResult<crate::channel::ChannelRows<crate::channel::SavedUpdate>> {
        self.read_saved(id, after)
    }
    fn channel_recent_rejections(
        &mut self,
        id: &crate::channel::ChannelId,
    ) -> StoreResult<crate::channel::RecentRejections> {
        self.read_recent_rejections(id)
    }
    fn channel_action(
        &mut self,
        id: &crate::channel::ChannelId,
        action: &crate::channel::ActionId,
    ) -> StoreResult<Read<crate::channel::ResumeAction>> {
        self.read_channel_action(id, action)
    }
    fn channel_message_action(
        &mut self,
        id: &crate::channel::ChannelId,
        message: &se_types::MessageId,
    ) -> StoreResult<Read<crate::channel::ResumeAction>> {
        self.read_message_action(id, message)
    }
    fn channel_confirmed_actions(
        &mut self,
        id: &crate::channel::ChannelId,
    ) -> StoreResult<Vec<crate::channel::ResumeAction>> {
        self.read_confirmed_actions(id)
    }
    fn channel_has_capacity(&mut self, id: &crate::channel::ChannelId) -> StoreResult<bool> {
        self.read_channel_capacity(id)
    }
    fn channel_due_delays(
        &mut self,
        id: &crate::channel::ChannelId,
        at_us: i64,
    ) -> StoreResult<Vec<se_types::MessageId>> {
        self.read_channel_due_delays(id, at_us)
    }
    fn channel_pending_outputs(
        &mut self,
        id: &crate::channel::ChannelId,
        at_us: i64,
    ) -> StoreResult<crate::channel::ChannelRows<crate::channel::Outbound>> {
        self.read_outputs(id, 0, None, Some(at_us))
    }
    fn channel_replies(
        &mut self,
        id: &crate::channel::ChannelId,
        original: &se_types::MessageId,
    ) -> StoreResult<crate::channel::ChannelRows<crate::channel::Outbound>> {
        self.read_outputs(id, 0, Some(original), None)
    }
    fn channel_outbox(
        &mut self,
        id: &crate::channel::ChannelId,
        after: u64,
    ) -> StoreResult<crate::channel::ChannelRows<crate::channel::Outbound>> {
        self.read_outbox(id, after)
    }
    fn channel_offset(&mut self, id: &crate::channel::ChannelId) -> StoreResult<Option<i64>> {
        self.read_channel_offset(id)
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
    fn event_position(&mut self, position: &StorePosition) -> StoreResult<Read<StoredEvent>> {
        if !position.belongs(&self.info) {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "position belongs to another store incarnation",
            ));
        }
        let event = self.record(i64::try_from(position.sequence()).map_err(invalid)?)?;
        if event.header.scope != self.scope.admission.scope {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "event position outside admitted scope",
            ));
        }
        Ok(Read::Present { value: event })
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
        self.head_with(
            "grants",
            "scope_key=? AND principal_id=? AND grant_key=?",
            &[&scope, &a, &codec::encode(&grant)?],
            None,
            &|seq| self.grant_event(seq, &principal, &grant),
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
        self.mail_source()?;
        let p = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let m = key(&self.db, "message", id.as_str(), &scope, false)?;
        let statement = if self.info.schema_version >= 3 {
            "SELECT d.sent_seq,d.revision,d.delivered_seq,d.read_seq,d.dismissed_seq FROM message_deliveries d WHERE d.project_id=? AND d.message_id=? LIMIT 1"
        } else {
            "SELECT d.sent_seq,d.revision,m.delivered_seq,m.read_seq,m.dismissed_seq FROM messages d JOIN marks m ON m.message_seq=d.sent_seq WHERE d.project_id=? AND d.message_id=?"
        };
        let row: Option<message::MarkRow> = self
            .db
            .query_row(statement, crate::sql_value::sql_params![p, m], |r| {
                Ok((
                    crate::sql_value::value(r, 0)?,
                    crate::sql_value::value(r, 1)?,
                    crate::sql_value::value(r, 2)?,
                    crate::sql_value::value(r, 3)?,
                    crate::sql_value::value(r, 4)?,
                ))
            })
            .optional()
            .map_err(|error| self.read_sql(error))?;
        match row {
            None => Ok(self.absent("message ID")),
            Some((s, v, d, r, x)) => Ok(Read::Present {
                value: self.message_at(s, v, d, r, x, None)?,
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
    fn resolve_request(&mut self, request: &RequestIdentity) -> StoreResult<Read<CommitReceipt>> {
        let probe = AtomicBatch {
            expected_incarnation: self.info.incarnation,
            admission: self.scope.admission.clone(),
            request: Some(request.clone()),
            events: vec![],
            import_checkpoint: None,
        };
        Ok(
            match crate::transaction::idempotency::lookup(&self.db, &probe, &self.info)? {
                Some(value) => Read::Present { value },
                None => self.absent("original request intent"),
            },
        )
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
        // A deadline handler belongs to this snapshot, never the next borrower.
        self.db
            .progress_handler(0, None::<fn() -> bool>)
            .map_err(|error| self.read_sql(error))?;
        ReadPhase {
            db: self.db,
            info: self.info,
            path: self.path,
            slot: self._slot,
            recycle: self.recycle,
            local: self._local,
        }
        .close()
    }
    fn history(
        &mut self,
        _query: HistoryQuery,
        _budget: ReadBudget,
    ) -> StoreResult<Page<StoredEvent>> {
        self.read_history(_query, _budget)
    }
    fn search(&mut self, query: SearchQuery, budget: ReadBudget) -> StoreResult<SearchPage> {
        self.read_search(query, budget)
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
    fn native_turn(
        &mut self,
        session: SessionId,
        provider: Provider,
        vendor: &str,
    ) -> StoreResult<Read<StoredEvent>> {
        self.read_session(session.clone())?;
        match codec::capture::native::find(
            &self.db,
            &self.scope.admission.scope,
            &session,
            provider,
            vendor,
        )? {
            Some(seq) => Ok(Read::Present {
                value: self.record(seq)?,
            }),
            None => Ok(self.absent("native conversation item")),
        }
    }
    fn recent_turns(
        &mut self,
        agent: AgentId,
        since: Option<StorePosition>,
        budget: ReadBudget,
    ) -> StoreResult<Page<StoredEvent>> {
        self.read_recent_turns(agent, since, budget)
    }
    fn transcript_events(
        &mut self,
        agent: AgentId,
        session: Option<SessionId>,
        budget: ReadBudget,
    ) -> StoreResult<TranscriptRecords> {
        self.read_transcript_events(agent, session, budget)
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
    fn capture_outcome(
        &mut self,
        source: RecordId,
        kind: Option<EventKind>,
    ) -> StoreResult<Read<StoredEvent>> {
        self.read_capture_outcome(source, kind)
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
        import: RecordId,
        budget: ReadBudget,
    ) -> StoreResult<Page<ImportCheckpoint>> {
        self.read_import_progress(import, budget)
    }
}

pub(crate) use crate::codec::event::load_event;
pub(crate) use cursor::checked_window_end;
