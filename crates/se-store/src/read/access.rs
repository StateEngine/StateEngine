//! Private snapshot access, visibility and projection decoding.
use super::*;

impl SqliteSnapshot {
    pub(super) fn read_sql(&self, error: rusqlite::Error) -> Box<StoreError> {
        let interrupted =
            error.sqlite_error_code() == Some(rusqlite::ErrorCode::OperationInterrupted);
        let mut mapped = sql(error);
        if interrupted {
            mapped.code = StoreErrorCode::ReadIncomplete;
            mapped.cause = "SQLite read deadline/step budget exhausted".into();
        }
        context(mapped, &self.path, StoreIoStage::ReadSnapshot)
    }
    pub(super) fn event_seq(&self, id: &EventId) -> StoreResult<Option<i64>> {
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

    pub(super) fn visible(&self, e: &StoredEvent) -> StoreResult<bool> {
        if matches!(e.body, EventBody::ChannelRecorded { .. }) {
            return Ok(matches!(self.scope.visibility, Visibility::Owner)
                && matches!(self.scope.admission.actor, Actor::Human(_))
                && self.scope.admission.session.is_none());
        }
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
                    EventBody::WorkMessageSent { work, .. } => work.addressees.contains(a),
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
    pub(super) fn agent_fact(
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
    pub(super) fn record(&self, seq: i64) -> StoreResult<StoredEvent> {
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
    pub(super) fn project_metadata(&self, seq: i64) -> StoreResult<StoredEvent> {
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
    pub(super) fn principal_metadata(&self, seq: i64) -> StoreResult<StoredEvent> {
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
    pub(super) fn absent<T>(&self, what: &str) -> Read<T> {
        Read::Absent {
            checked: format!(
                "{what}; store {} incarnation {} finite snapshot",
                self.info.id, self.info.incarnation
            ),
        }
    }
    pub(super) fn head(
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
    pub(super) fn head_with(
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
    pub(super) fn project_bytes(&self) -> StoreResult<Vec<u8>> {
        connection::project_id(&self.db, &self.scope.admission.scope, false)
    }
    pub(super) fn agent_bytes(&self, a: &AgentId) -> StoreResult<Vec<u8>> {
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
    pub(super) fn message_at(
        &self,
        sent: i64,
        revision: u64,
        delivered: Option<u64>,
        read: Option<u64>,
        dismissed: Option<u64>,
        selected_recipient: Option<&[u8]>,
    ) -> StoreResult<MessageRecord> {
        let e = self.record(sent)?;
        let (message, recipient, work, kind, body, refs, reply_to, quiet) = match e.body {
            EventBody::MessageSent {
                message,
                recipient,
                kind,
                body,
                refs,
                reply_to,
                quiet,
            } => (message, recipient, None, kind, body, refs, reply_to, quiet),
            EventBody::WorkMessageSent {
                message,
                work,
                kind,
                body,
                refs,
                reply_to,
                quiet,
            } => {
                let preview = match &self.scope.visibility {
                    Visibility::SelfOnly(agent) => Some(Actor::Agent(agent.clone())),
                    _ => None,
                };
                let agent = if let Some(selected) = selected_recipient {
                    let agent = wire(
                        &self.db,
                        "agent",
                        selected,
                        &scope_key(&self.db, &e.header.scope, false)?,
                    )?
                    .try_into()
                    .map_err(invalid)?;
                    if !work.addressees.contains(&agent) {
                        return Err(invalid("work delivery names an unaddressed recipient"));
                    }
                    agent
                } else {
                    match preview.as_ref() {
                        Some(Actor::Agent(agent)) if work.addressees.contains(agent) => {
                            agent.clone()
                        }
                        _ => work
                            .addressees
                            .first()
                            .cloned()
                            .ok_or_else(|| invalid("work message has no addressees"))?,
                    }
                };
                (
                    message,
                    Actor::Agent(agent),
                    Some(work),
                    kind,
                    body,
                    refs,
                    reply_to,
                    quiet,
                )
            }
            _ => return Err(invalid("message head points to another event kind")),
        };
        let (delivered, read, dismissed) = if work.is_some() {
            let id = key(
                &self.db,
                recipient.kind(),
                recipient.wire(),
                &scope_key(&self.db, &e.header.scope, false)?,
                false,
            )?;
            self.db.query_row("SELECT delivered_seq,read_seq,dismissed_seq FROM message_deliveries WHERE sent_seq=? AND recipient_id=?",rusqlite::params![sent,id],|r|Ok((crate::sql_value::value(r,0)?,crate::sql_value::value(r,1)?,crate::sql_value::value(r,2)?))).map_err(sql)?
        } else {
            (delivered, read, dismissed)
        };
        let pos = |s| StorePosition::new_internal(self.info.id.clone(), self.info.incarnation, s);
        let replacement: Option<Vec<u8>> = self
            .db
            .query_row(
                if self.info.schema_version >= 3 {
                    "SELECT superseded_by FROM message_deliveries WHERE sent_seq=? LIMIT 1"
                } else {
                    "SELECT superseded_by FROM messages WHERE sent_seq=?"
                },
                [sent],
                |r| r.get(0),
            )
            .map_err(sql)?;
        let scope = scope_key(&self.db, &e.header.scope, false)?;
        let superseded_by = replacement
            .map(|bytes| {
                wire(&self.db, "message", &bytes, &scope)?
                    .try_into()
                    .map_err(invalid)
            })
            .transpose()?;
        let notifications =
            self.notification_rows(sent, &e.header.actor, &recipient, work.as_ref(), quiet)?;
        Ok(MessageRecord {
            message,
            event: e.header.event,
            revision: codec::revision(revision)?,
            sent: e.position,
            sender: e.header.actor,
            recipient,
            work,
            kind,
            body,
            refs,
            reply_to,
            delivered: delivered.map(pos).transpose()?,
            read: read.map(pos).transpose()?,
            dismissed: dismissed.map(pos).transpose()?,
            superseded_by,
            body_complete: true,
            quiet,
            notifications,
        })
    }
}
