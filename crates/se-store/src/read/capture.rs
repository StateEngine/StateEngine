use super::*;
impl SqliteSnapshot {
    pub(super) fn read_capture_outcome(
        &self,
        source: RecordId,
        kind: Option<EventKind>,
    ) -> StoreResult<Read<StoredEvent>> {
        let kind = match kind {
            None => None,
            Some(EventKind::CaptureFailed) => Some("capture.failed"),
            Some(EventKind::CaptureVerified) => Some("capture.verified"),
            _ => return Err(invalid("capture outcome kind")),
        };
        let record = match self.read_capture_source(source)? {
            Read::Present { value } => value,
            Read::Absent { .. } => {
                return Err(fail(
                    StoreErrorCode::ReferenceMissing,
                    "capture source is absent; no final outcome can be inferred",
                ));
            }
            _ => {
                return Err(fail(
                    StoreErrorCode::ProjectionInconsistent,
                    "capture source is unavailable",
                ));
            }
        };
        let original = record.original.as_deref().unwrap_or(&record.current);
        let EventBody::CaptureSource { session, .. } = &original.body else {
            return Err(fail(
                StoreErrorCode::ProjectionInconsistent,
                "capture source original registration is unavailable",
            ));
        };
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let id = key(&self.db, "session", session.as_str(), &scope, false)?;
        let seq: Option<i64> = self.db.query_row("SELECT seq FROM events INDEXED BY events_session_seq WHERE project_id=? AND session_id=? AND seq>? AND kind IN ('capture.failed','capture.verified') AND (? IS NULL OR kind=?) ORDER BY seq DESC LIMIT 1",crate::sql_value::sql_params![self.project_bytes()?,id,record.current.position.sequence(),kind,kind],|row|row.get(0)).optional().map_err(|error|self.read_sql(error))?;
        let Some(seq) = seq else {
            return Ok(self.absent("capture outcome after the current source cursor"));
        };
        let event = self.record(seq)?;
        if !matches!(&event.body, EventBody::CaptureFailed {source:found,session:recorded,..} | EventBody::CaptureVerified {source:found,session:recorded,..} if *found==source && recorded==session)
        {
            return Err(fail(
                StoreErrorCode::ProjectionInconsistent,
                "capture outcome differs from the exact protected source/session",
            ));
        }
        Ok(Read::Present { value: event })
    }
    pub(super) fn session_visible(
        &self,
        session: &SessionId,
        agent: &AgentId,
    ) -> StoreResult<bool> {
        let p = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let id = key(&self.db, "session", session.as_str(), &scope, false)?;
        let a = self.agent_bytes(agent)?;
        self.db.query_row("SELECT EXISTS(SELECT 1 FROM sessions WHERE project_id=? AND session_id=? AND agent_id=?)",rusqlite::params![p,id,a],|r|r.get(0)).map_err(|error| self.read_sql(error))
    }
    pub(super) fn source_visible(&self, source: &RecordId, agent: &AgentId) -> StoreResult<bool> {
        let p = self.project_bytes()?;
        let a = self.agent_bytes(agent)?;
        self.db.query_row("SELECT EXISTS(SELECT 1 FROM capture_sources c JOIN sessions s ON s.project_id=c.project_id AND s.session_id=c.session_id WHERE c.project_id=? AND c.source_id=? AND s.agent_id=?)",rusqlite::params![p,source.as_bytes().as_slice(),a],|r|r.get(0)).map_err(|error| self.read_sql(error))
    }
    pub(super) fn read_session(&self, id: SessionId) -> StoreResult<Read<ProjectionRecord>> {
        let p = self.project_bytes()?;
        let scope = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let session = key(&self.db, "session", id.as_str(), &scope, false)?;
        if let Visibility::SelfOnly(agent) = &self.scope.visibility
            && !self.session_visible(&id, agent)?
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "session belongs to another principal or is absent",
            ));
        }
        self.head(
            "sessions",
            "project_id=? AND session_id=?",
            &[&p, &session],
            Some("first_seq"),
        )
    }
    pub(super) fn read_capture_source(&self, id: RecordId) -> StoreResult<Read<ProjectionRecord>> {
        let p = self.project_bytes()?;
        let row:Option<(u64,i64,Vec<u8>)>=self.db.query_row("SELECT revision,last_seq,source_incarnation FROM capture_sources WHERE project_id=? AND source_id=?",rusqlite::params![p,id.as_bytes().as_slice()],|r|Ok((crate::sql_value::value(r,0)?,r.get(1)?,r.get(2)?))).optional().map_err(|error| self.read_sql(error))?;
        let Some((revision, last, incarnation)) = row else {
            return Ok(self.absent("capture source"));
        };
        if let Visibility::SelfOnly(agent) = &self.scope.visibility
            && !self.source_visible(&id, agent)?
        {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "capture source belongs to another principal",
            ));
        }
        let first:Option<i64>=self.db.query_row("SELECT MAX(event_seq) FROM aux_data INDEXED BY capture_source_natural WHERE json_extract(facts,'$.capture_kind')='source' AND json_extract(facts,'$.project')=? AND json_extract(facts,'$.source')=? AND json_extract(facts,'$.incarnation')=? AND event_seq<=?",rusqlite::params![project(&self.scope.admission.scope)?.as_str(),codec::encode(&id)?,codec::encode(&incarnation)?,last],|r|r.get(0)).map_err(|error| self.read_sql(error))?;
        let first = first.ok_or_else(|| {
            fail(
                StoreErrorCode::ProjectionInconsistent,
                "capture source registration fact is absent",
            )
        })?;
        Ok(Read::Present {
            value: ProjectionRecord {
                revision: codec::revision(revision)?,
                current: self.record(last)?,
                original: if first == last {
                    None
                } else {
                    Some(Box::new(self.record(first)?))
                },
            },
        })
    }
    pub(super) fn read_turn(&self, id: RecordId) -> StoreResult<Read<StoredEvent>> {
        let project = self.project_bytes()?;
        let seq: Option<i64> = self
            .db
            .query_row(
                "SELECT event_seq FROM turn_data INDEXED BY turn_data_id
             WHERE project_id=? AND turn_id=?",
                rusqlite::params![project, id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| self.read_sql(error))?;
        let Some(seq) = seq else {
            return Ok(self.absent("turn"));
        };
        let event = self.record(seq)?;
        if event.header.scope != self.scope.admission.scope
            || !matches!(&event.body, EventBody::SessionTurn { turn, .. } if *turn == id)
        {
            return Err(fail(
                StoreErrorCode::ProjectionInconsistent,
                "turn index differs from its immutable event",
            ));
        }
        Ok(Read::Present { value: event })
    }
    pub(super) fn read_turns(
        &mut self,
        agent: AgentId,
        budget: ReadBudget,
    ) -> StoreResult<Page<StoredEvent>> {
        let deadline = query::deadline(&budget)?;
        let p = self.project_bytes()?;
        let a = self.agent_bytes(&agent)?;
        let binding = format!("history:turns:{}", agent.as_str());
        let (h, after) = self.window(&budget, &binding, false)?;
        let rows=self.query_seqs_before("SELECT e.entity_revision,t.event_seq,t.event_seq FROM turn_data t INDEXED BY turn_data_agent_seq JOIN events e ON e.seq=t.event_seq WHERE t.project_id=? AND t.agent_id=? AND t.event_seq>? AND t.event_seq<=? ORDER BY t.event_seq LIMIT ?",vec![rusqlite::types::Value::Blob(p),rusqlite::types::Value::Blob(a),rusqlite::types::Value::Integer(after as i64),rusqlite::types::Value::Integer(h as i64),rusqlite::types::Value::Integer(i64::from(budget.page.limit.get())+1)],deadline)?;
        let mut items = Vec::new();
        let mut bytes = 0;
        let mut last = after;
        let mut stop = StopReason::Exhausted;
        for (_, seq, _) in rows {
            if Instant::now() >= deadline {
                return Err(fail(
                    StoreErrorCode::ReadIncomplete,
                    "turn read deadline exhausted",
                ));
            }
            if items.len() == budget.page.limit.get() as usize {
                stop = StopReason::ItemLimit;
                break;
            }
            let e = self.record(seq)?;
            let cost = query::event_size(&e)?;
            if bytes + cost > u64::from(budget.page.max_bytes.get()) {
                if items.is_empty() {
                    return Err(query::budget_failure(
                        &budget,
                        cost,
                        "first complete turn exceeds page bytes",
                    ));
                }
                stop = StopReason::ByteLimit;
                break;
            }
            bytes += cost;
            last = seq as u64;
            items.push(e);
        }
        query::check_deadline(deadline)?;
        self.page(
            items,
            &budget,
            &binding,
            page::PageFacts {
                h,
                after,
                last,
                bytes,
                stop,
                remaining: None,
            },
        )
    }
}
