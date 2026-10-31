use crate::{codec, connection, error::*, identity::*, open::SqliteReader, *};
use rusqlite::{Connection, OptionalExtension, params};
use se_types::{
    AgentId, Cursor, EventId, Omission, OmissionReason, Page, ProjectId, Read, Sequence, Source,
    StopReason, Window, WindowFields,
};
use se_types::{DecisionId, LifecycleId, SessionId};
use std::{
    marker::PhantomData,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};
pub struct SqliteSnapshot {
    pub(crate) db: Connection,
    info: StoreInfo,
    scope: ReadScope,
    slots: Arc<AtomicUsize>,
    _local: PhantomData<Rc<()>>,
}
impl SqliteSnapshot {
    pub(crate) fn open(reader: &SqliteReader, scope: ReadScope) -> StoreResult<Self> {
        if reader
            .slots
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < 2).then_some(n + 1)
            })
            .is_err()
        {
            return Err(fail(
                StoreErrorCode::Backpressure,
                "two finite store read snapshots are already in use",
            ));
        }
        let result = (|| {
            let db = connection::connect(&reader.path, false, reader.timeout)?;
            db.execute_batch("BEGIN").map_err(sql)?;
            let info = connection::info(&db)?;
            if info.state != StoreState::Ready {
                return Err(fail(StoreErrorCode::NotReady, "store is in maintenance"));
            }
            Ok(Self {
                db,
                info,
                scope,
                slots: reader.slots.clone(),
                _local: PhantomData,
            })
        })();
        if result.is_err() {
            reader.slots.fetch_sub(1, Ordering::AcqRel);
        }
        result
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
        self.db
            .query_row(
                "SELECT seq FROM events WHERE event_id=? AND project_id IS ?",
                params![key, p],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql)
    }
    fn visible(&self, e: &StoredEvent) -> bool {
        match &self.scope.visibility {
            Visibility::Owner | Visibility::SharedProject(_) => true,
            Visibility::SelfOnly(a) => {
                let who = Actor::Agent(a.clone());
                e.header.actor == who
                    || match &e.body {
                        EventBody::MessageSent { recipient, .. } => *recipient == who,
                        EventBody::WorkingStateSet { agent, .. } => agent == a,
                        EventBody::PrincipalRegistered { principal, .. } => *principal == who,
                        _ => false,
                    }
            }
        }
    }
    fn record(&self, seq: i64) -> StoreResult<StoredEvent> {
        let e = load_event(&self.db, seq, &self.info)?;
        if matches!(
            e.body,
            EventBody::RuntimeOwnerEstablished { .. } | EventBody::RuntimeHandoverRecorded { .. }
        ) {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "runtime ownership facts are private maintenance data",
            ));
        }
        if !self.visible(&e) {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "event is outside admitted visibility",
            ));
        }
        Ok(e)
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
        let row: Option<(u64, i64, Option<i64>)> = self
            .db
            .query_row(
                &format!(
                    "SELECT revision,last_seq,{} FROM {table} WHERE {filter}",
                    original.unwrap_or("NULL")
                ),
                keys,
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(sql)?;
        match row {
            None => Ok(self.absent(table)),
            Some((revision, seq, first)) => Ok(Read::Present {
                value: ProjectionRecord {
                    revision: codec::revision(revision)?,
                    current: self.record(seq)?,
                    original: first
                        .filter(|s| *s != seq)
                        .map(|s| self.record(s).map(Box::new))
                        .transpose()?,
                },
            }),
        }
    }
    fn project_bytes(&self) -> StoreResult<Vec<u8>> {
        connection::project_id(&self.db, &self.scope.admission.scope, false)
    }
    fn agent_bytes(&self, a: &AgentId) -> StoreResult<Vec<u8>> {
        if let Visibility::SelfOnly(own) = &self.scope.visibility {
            if own != a {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "private agent read refused",
                ));
            }
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
    fn page<T>(
        &self,
        items: Vec<T>,
        budget: &ReadBudget,
        binding: &str,
        h: u64,
        after: u64,
        last: u64,
        more: bool,
        bytes: u64,
        stop: StopReason,
    ) -> StoreResult<Page<T>> {
        let next = if more {
            Some(self.cursor(binding, h, last)?)
        } else {
            None
        };
        let window = Window::new(WindowFields {
            source: Source::Store {
                store: self.info.id.clone(),
                project: match &self.scope.admission.scope {
                    Scope::Project(p) => Some(p.clone()),
                    _ => None,
                },
            },
            from: Sequence::new(after).map_err(invalid)?,
            to: Sequence::new(h).map_err(invalid)?,
            start_cursor: budget.page.after.clone(),
            end_cursor: next.clone(),
            returned: items.len() as u64,
            limit: budget.page.limit,
            bytes,
            max_bytes: budget.page.max_bytes,
            omitted_before: Omission::None,
            omitted_after: if more {
                Omission::Unknown {
                    reason: if stop == StopReason::ItemLimit {
                        OmissionReason::Limit
                    } else {
                        OmissionReason::Budget
                    },
                }
            } else {
                Omission::None
            },
            unreadable: 0,
            stop_reason: stop,
        })
        .map_err(invalid)?;
        Page::new(items, window, next).map_err(invalid)
    }
    fn cursor(&self, binding: &str, h: u64, after: u64) -> StoreResult<Cursor> {
        // Encoded internal coordinates have no public numeric interpretation.
        let raw = codec::encode(&(
            self.info.id.as_str(),
            self.info.incarnation,
            binding,
            h,
            after,
        ))?;
        Cursor::new(
            raw.as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        )
        .map_err(invalid)
    }
    fn window(&self, budget: &ReadBudget, binding: &str, live: bool) -> StoreResult<(u64, u64)> {
        if budget.page.limit.get() > 1000
            || budget.page.max_bytes.get() > 2 * 1024 * 1024
            || budget.deadline.is_zero()
        {
            return Err(fail(
                StoreErrorCode::ReadBudgetTooSmall,
                "page needs limit 1..1000, bytes 1..2MiB, and a finite nonzero deadline",
            ));
        }
        let h = self
            .info
            .head
            .as_ref()
            .map(StorePosition::sequence)
            .unwrap_or(0);
        let Some(cursor) = &budget.page.after else {
            return Ok((h, 0));
        };
        let mut bytes = Vec::new();
        for pair in cursor.as_str().as_bytes().chunks(2) {
            if pair.len() != 2 {
                return Err(fail(StoreErrorCode::CursorInvalid, "malformed cursor"));
            }
            let s = std::str::from_utf8(pair).map_err(invalid)?;
            bytes.push(u8::from_str_radix(s, 16).map_err(invalid)?)
        }
        let (store, inc, query, prior, last): (String, u64, String, u64, u64) =
            serde_json::from_slice(&bytes)
                .map_err(|_| fail(StoreErrorCode::CursorInvalid, "cursor cannot be decoded"))?;
        if store != self.info.id.as_str() || inc != self.info.incarnation {
            return Err(fail(
                StoreErrorCode::CursorStale,
                "cursor store/incarnation changed",
            ));
        }
        if query != binding || last > prior || prior > h {
            return Err(fail(
                StoreErrorCode::CursorInvalid,
                "cursor scope/query/window mismatch",
            ));
        }
        Ok((if live { h } else { prior }, last))
    }
}
impl Drop for SqliteSnapshot {
    fn drop(&mut self) {
        let _ = self.db.execute_batch("ROLLBACK");
        self.slots.fetch_sub(1, Ordering::AcqRel);
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
        self.snapshot.db.query_row("SELECT EXISTS(SELECT 1 FROM identities WHERE kind=? AND wire_id=? AND scope_key=? AND encoding='registered-exception')",params![kind,text,scope],|r|r.get(0)).map_err(|e|se_types::SeError::invalid("legacy registry",&e.to_string()))
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
        if let (Visibility::SelfOnly(a), Actor::Agent(other)) = (&self.scope.visibility, &id) {
            if a != other {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "principal private read refused",
                ));
            }
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
        let row:Option<(i64,u64,Option<u64>,Option<u64>,Option<u64>)>=self.db.query_row("SELECT d.sent_seq,d.revision,m.delivered_seq,m.read_seq,m.dismissed_seq FROM messages d JOIN marks m ON m.message_seq=d.sent_seq WHERE d.project_id=? AND d.message_id=?",params![p,m],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional().map_err(sql)?;
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
        let p = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let binding = codec::encode(&(
            &scope,
            &self.scope.admission.actor,
            &query.recipient,
            &query.sender,
            &query.kind,
            query.unread_only,
            query.full_body,
        ))?;
        let (h, after) = self.window(&budget, &binding, false)?;
        let to = query
            .recipient
            .as_ref()
            .map(|a| {
                key(
                    &self.db,
                    a.kind(),
                    a.wire(),
                    if a.kind() == "human" { &[0] } else { &scope },
                    false,
                )
            })
            .transpose()?;
        let from = query
            .sender
            .as_ref()
            .map(|a| {
                key(
                    &self.db,
                    a.kind(),
                    a.wire(),
                    if a.kind() == "human" { &[0] } else { &scope },
                    false,
                )
            })
            .transpose()?;
        let own = match &self.scope.visibility {
            Visibility::SelfOnly(a) => Some(self.agent_bytes(a)?),
            _ => None,
        };
        let start = Instant::now();
        let deadline = start + budget.deadline;
        self.db
            .progress_handler(1000, Some(move || Instant::now() >= deadline))
            .map_err(sql)?;
        let rows = (|| {
            let mut stmt=self.db.prepare("SELECT sort_seq,revision,delivered_seq,read_seq,dismissed_seq FROM list_versions WHERE scope_key=? AND family='message' AND sort_seq>? AND sort_seq<=? AND valid_from<=? AND (valid_to IS NULL OR ?<valid_to) AND (? IS NULL OR recipient_id=?) AND (? IS NULL OR sender_id=?) AND (? IS NULL OR message_kind=?) AND (?=0 OR state='unread') AND (? IS NULL OR sender_id=? OR recipient_id=?) ORDER BY sort_seq,entity_key LIMIT ?").map_err(sql)?;
            stmt.query_map(
                params![
                    scope,
                    after,
                    h,
                    h,
                    h,
                    to,
                    to,
                    from,
                    from,
                    query.kind,
                    query.kind,
                    query.unread_only,
                    own,
                    own,
                    own,
                    u64::from(budget.page.limit.get()) + 1
                ],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, u64>(1)?,
                        r.get::<_, Option<u64>>(2)?,
                        r.get::<_, Option<u64>>(3)?,
                        r.get::<_, Option<u64>>(4)?,
                    ))
                },
            )
            .map_err(sql)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(sql)
        })();
        self.db
            .progress_handler(0, None::<fn() -> bool>)
            .map_err(sql)?;
        let rows = rows?;
        let mut items = Vec::new();
        let mut bytes = 0;
        let mut last = after;
        let mut more = false;
        let mut stop = StopReason::Exhausted;
        for (sent, rev, d, r, x) in rows {
            if items.len() == budget.page.limit.get() as usize {
                more = true;
                stop = StopReason::ItemLimit;
                break;
            }
            if start.elapsed() >= budget.deadline {
                return Err(fail(
                    StoreErrorCode::ReadIncomplete,
                    "mail read deadline exhausted",
                ));
            }
            let mut m = self.message_at(sent, rev, d, r, x)?;
            let body_bytes = match &m.body {
                StoredText::Present(s) => s.len(),
                StoredText::Erased { .. } => 0,
            };
            let cost = body_bytes as u64 + 1024;
            if cost + bytes > u64::from(budget.page.max_bytes.get()) {
                if items.is_empty() {
                    return Err(fail(
                        StoreErrorCode::ReadBudgetTooSmall,
                        "first complete message exceeds page byte budget",
                    ));
                }
                more = true;
                stop = StopReason::ByteLimit;
                break;
            }
            if !query.full_body {
                if let StoredText::Present(s) = &mut m.body {
                    if s.len() > 256 {
                        let mut end = 256;
                        while !s.is_char_boundary(end) {
                            end -= 1
                        }
                        s.truncate(end);
                        m.body_complete = false
                    }
                }
            }
            bytes += cost;
            last = sent as u64;
            items.push(m);
        }
        let _ = p;
        self.page(items, &budget, &binding, h, after, last, more, bytes, stop)
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
        let op:Option<Vec<u8>>=self.db.query_row("SELECT operation_id FROM operations WHERE scope_key=? AND actor_id=? AND request_key=? AND erased=0",params![scope,a,request.as_str()],|r|r.get(0)).optional().map_err(sql)?;
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
        let row:Option<(Option<u64>,Option<u64>,Option<u64>,Option<u64>,u64,u64,u64)>=self.db.query_row("SELECT last_turn_seq,last_working_state_seq,last_cursor_seq,last_session_seq,unread_count,pending_effect_count,last_seq FROM resume_heads WHERE project_id=? AND principal_id=?",params![p,a],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?))).optional().map_err(sql)?;
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
        self.db.execute_batch("ROLLBACK").map_err(sql)
    }
    fn history(
        &mut self,
        _query: HistoryQuery,
        _budget: ReadBudget,
    ) -> StoreResult<Page<StoredEvent>> {
        later("history")
    }
    fn search(&mut self, _query: SearchQuery, _budget: ReadBudget) -> StoreResult<Page<SearchHit>> {
        later("search")
    }
    fn projects(&mut self, _budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        later("projects")
    }
    fn principals(&mut self, _budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        later("principals")
    }
    fn session(&mut self, _id: SessionId) -> StoreResult<Read<ProjectionRecord>> {
        later("session")
    }
    fn sessions(&mut self, _budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        later("sessions")
    }
    fn decision(&mut self, _id: DecisionId) -> StoreResult<Read<ProjectionRecord>> {
        later("decision")
    }
    fn decisions(
        &mut self,
        _query: DecisionQuery,
        _budget: ReadBudget,
    ) -> StoreResult<Page<ProjectionRecord>> {
        later("decisions")
    }
    fn turns(&mut self, _agent: AgentId, _budget: ReadBudget) -> StoreResult<Page<StoredEvent>> {
        later("turns")
    }
    fn capture_source(&mut self, _source: RecordId) -> StoreResult<Read<ProjectionRecord>> {
        later("capture_source")
    }
    fn process(&mut self, _id: LifecycleId) -> StoreResult<Read<ProjectionRecord>> {
        later("process")
    }
    fn processes(&mut self, _budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        later("processes")
    }
    fn cursor(&mut self, _agent: AgentId, _purpose: String) -> StoreResult<Read<CursorRecord>> {
        later("cursor")
    }
    fn pending_effects(&mut self, _budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        later("pending_effects")
    }
    fn effect(&mut self, _id: RecordId) -> StoreResult<Read<ProjectionRecord>> {
        later("effect")
    }
    fn integrations(&mut self, _budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        later("integrations")
    }
    fn import_progress(
        &mut self,
        _import: RecordId,
        _budget: ReadBudget,
    ) -> StoreResult<Page<ImportCheckpoint>> {
        later("import_progress")
    }
}

pub(crate) fn load_event(c: &Connection, seq: i64, info: &StoreInfo) -> StoreResult<StoredEvent> {
    let (id,p,actor_id,session,origin,door,kind,version,inc,rev,mode,generation,durability,occurred,recorded,cause,supersedes):(Vec<u8>,Option<Vec<u8>>,Vec<u8>,Option<Vec<u8>>,Vec<u8>,String,String,u32,u64,u64,String,Option<u64>,String,i64,i64,Option<Vec<u8>>,Option<Vec<u8>>)=c.query_row("SELECT event_id,project_id,actor_id,session_id,origin_id,door,kind,schema_version,recorded_incarnation,entity_revision,writer_mode,host_generation,durability,occurred_at_us,recorded_at_us,cause_event_id,supersedes_event_id FROM events WHERE seq=?",[seq],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,r.get(12)?,r.get(13)?,r.get(14)?,r.get(15)?,r.get(16)?))).map_err(sql)?;
    if version != 1 {
        return Err(fail(
            StoreErrorCode::Unreadable,
            "unknown event schema version",
        ));
    }
    let scope = match p {
        Some(p) => Scope::Project(wire(c, "project", &p, &[0])?.parse().map_err(invalid)?),
        None => Scope::Registry,
    };
    let s = scope_key(c, &scope, false)?;
    let parse_event = |k: &[u8]| wire(c, "event", k, &s).and_then(|v| v.parse().map_err(invalid));
    let writer = match (mode.as_str(), generation) {
        ("direct", None) => LeaseIdentity {
            store: Some(info.id.clone()),
            generation: 1,
            mode: LeaseMode::DirectClient,
        },
        ("host", Some(g)) if g > 0 => LeaseIdentity {
            store: Some(info.id.clone()),
            generation: g,
            mode: LeaseMode::Host,
        },
        _ => return Err(invalid("invalid persisted writer stamp")),
    };
    Ok(StoredEvent {
        header: EventHeader {
            event: parse_event(&id)?,
            scope: scope.clone(),
            actor: actor(c, &actor_id, &s)?,
            session: session
                .map(|v| wire(c, "session", &v, &s).and_then(|v| v.parse().map_err(invalid)))
                .transpose()?,
            origin: StoreId::from_bytes(
                origin.try_into().map_err(|_| invalid("origin ID length"))?,
            )
            .map_err(invalid)?,
            door: match door.as_str() {
                "cli" => Door::Cli,
                "mcp" => Door::Mcp,
                "hook" => Door::Hook,
                "host" => Door::Host,
                "import" => Door::Import,
                _ => return Err(invalid("invalid stored door")),
            },
            occurred_at_us: occurred,
            cause: cause.map(|v| parse_event(&v)).transpose()?,
            supersedes: supersedes.map(|v| parse_event(&v)).transpose()?,
        },
        revision: codec::revision(rev)?,
        position: StorePosition::new_internal(info.id.clone(), inc, seq as u64)?,
        recorded_at_us: recorded,
        recorded_incarnation: inc,
        writer: WriterMode::from_lease(&writer),
        durability: match durability.as_str() {
            "normal" => CommitDurability::Normal,
            "full" => CommitDurability::Full,
            _ => return Err(invalid("invalid persisted durability")),
        },
        body: codec::body(c, seq, &kind, &scope)?,
        erased_fields: Vec::new(),
    })
}
