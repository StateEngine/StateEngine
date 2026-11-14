//! Snapshot-port operations on the same scoped SQLite read pin.
use super::*;

impl Snapshot for SqliteSnapshot {
    type LegacyRegistry<'a> = LegacyRegistry<'a>;
    fn legacy_registry(&self) -> StoreResult<Self::LegacyRegistry<'_>> {
        self.require_local_port()?;
        Ok(LegacyRegistry { snapshot: self })
    }
    fn channel_reply_route(
        &mut self,
        message: &se_types::MessageId,
    ) -> StoreResult<Option<crate::channel::ReplyRoute>> {
        self.require_local_port()?;
        self.read_channel_route(message)
    }
    fn channel_active(&mut self) -> StoreResult<Vec<crate::channel::Connection>> {
        self.require_local_port()?;
        self.read_active_channels()
    }
    fn channel_update_handled(
        &mut self,
        id: &crate::channel::ChannelId,
        update: &crate::channel::ExternalId,
    ) -> StoreResult<bool> {
        self.require_local_port()?;
        self.read_update_handled(id, update)
    }
    fn channel_version(&mut self) -> StoreResult<crate::channel::Version> {
        self.require_local_port()?;
        self.read_channel_version()
    }
    fn channel_connection(
        &mut self,
        id: &crate::channel::ChannelId,
    ) -> StoreResult<Read<crate::channel::Connection>> {
        self.require_local_port()?;
        self.read_channel(id)
    }
    fn channel_connections(
        &mut self,
        after: u64,
    ) -> StoreResult<crate::channel::ChannelRows<crate::channel::Connection>> {
        self.require_local_port()?;
        self.read_channels(after)
    }
    fn channel_receipt(
        &mut self,
        id: &crate::channel::ChannelId,
        receipt: &crate::channel::ReceiptId,
    ) -> StoreResult<Read<crate::channel::SavedUpdate>> {
        self.require_local_port()?;
        self.read_saved_receipt(id, receipt)
    }
    fn channel_saved(
        &mut self,
        id: &crate::channel::ChannelId,
        after: u64,
    ) -> StoreResult<crate::channel::ChannelRows<crate::channel::SavedUpdate>> {
        self.require_local_port()?;
        self.read_saved(id, after)
    }
    fn channel_recent_rejections(
        &mut self,
        id: &crate::channel::ChannelId,
    ) -> StoreResult<crate::channel::RecentRejections> {
        self.require_local_port()?;
        self.read_recent_rejections(id)
    }
    fn channel_action(
        &mut self,
        id: &crate::channel::ChannelId,
        action: &crate::channel::ActionId,
    ) -> StoreResult<Read<crate::channel::ResumeAction>> {
        self.require_local_port()?;
        self.read_channel_action(id, action)
    }
    fn channel_message_action(
        &mut self,
        id: &crate::channel::ChannelId,
        message: &se_types::MessageId,
    ) -> StoreResult<Read<crate::channel::ResumeAction>> {
        self.require_local_port()?;
        self.read_message_action(id, message)
    }
    fn channel_confirmed_actions(
        &mut self,
        id: &crate::channel::ChannelId,
    ) -> StoreResult<Vec<crate::channel::ResumeAction>> {
        self.require_local_port()?;
        self.read_confirmed_actions(id)
    }
    fn channel_has_capacity(&mut self, id: &crate::channel::ChannelId) -> StoreResult<bool> {
        self.require_local_port()?;
        self.read_channel_capacity(id)
    }
    fn channel_due_delays(
        &mut self,
        id: &crate::channel::ChannelId,
        at_us: i64,
    ) -> StoreResult<Vec<se_types::MessageId>> {
        self.require_local_port()?;
        self.read_channel_due_delays(id, at_us)
    }
    fn channel_pending_outputs(
        &mut self,
        id: &crate::channel::ChannelId,
        at_us: i64,
    ) -> StoreResult<crate::channel::ChannelRows<crate::channel::Outbound>> {
        self.require_local_port()?;
        self.read_outputs(id, 0, None, Some(at_us))
    }
    fn channel_replies(
        &mut self,
        id: &crate::channel::ChannelId,
        original: &se_types::MessageId,
    ) -> StoreResult<crate::channel::ChannelRows<crate::channel::Outbound>> {
        self.require_local_port()?;
        self.read_outputs(id, 0, Some(original), None)
    }
    fn channel_outbox(
        &mut self,
        id: &crate::channel::ChannelId,
        after: u64,
    ) -> StoreResult<crate::channel::ChannelRows<crate::channel::Outbound>> {
        self.require_local_port()?;
        self.read_outbox(id, after)
    }
    fn channel_cursor(
        &mut self,
        id: &crate::channel::ChannelId,
    ) -> StoreResult<Option<crate::channel::ReceiveCursor>> {
        self.require_local_port()?;
        self.read_channel_cursor(id)
    }
    fn info(&self) -> StoreInfo {
        self.info.clone()
    }
    fn position_cursor(
        &self,
        position: &StorePosition,
        purpose: PositionPurpose,
    ) -> StoreResult<Cursor> {
        self.require_local_port()?;
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
        self.require_local_port()?;
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
        self.require_local_port()?;
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
        self.require_local_port()?;
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
        self.require_local_port()?;
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
    fn remote_message_attribution(
        &mut self,
        id: se_types::MessageId,
    ) -> StoreResult<Option<se_types::remote::RemoteAttribution>> {
        self.require_local_port()?;
        self.read_remote_message_attribution(id)
    }
    fn remote_return_sender(
        &mut self,
        message: se_types::MessageId,
    ) -> StoreResult<Option<se_types::remote::RemoteAgentAddress>> {
        self.read_return_sender(message)
    }
    fn remote_reply_recipient(
        &mut self,
        original: se_types::MessageId,
        selector: &str,
    ) -> StoreResult<Option<Actor>> {
        self.read_remote_reply_recipient(original, selector)
    }
    fn messages(
        &mut self,
        query: MessageQuery,
        budget: ReadBudget,
    ) -> StoreResult<Page<MessageRecord>> {
        self.require_local_port()?;
        self.read_messages(query, budget)
    }
    fn message_count(&mut self, query: MessageQuery) -> StoreResult<u64> {
        self.require_local_port()?;
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
        self.require_local_port()?;
        self.read_resume_head(principal)
    }
    fn close(mut self) -> StoreResult<()> {
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
        self.require_local_port()?;
        self.read_history(_query, _budget)
    }
    fn search(&mut self, query: SearchQuery, budget: ReadBudget) -> StoreResult<SearchPage> {
        self.require_local_port()?;
        self.read_search(query, budget)
    }
    fn projects(&mut self, _budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        self.require_local_port()?;
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
        self.require_local_port()?;
        self.read_removed_projects(query, budget)
    }
    fn principals(&mut self, _budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        self.require_local_port()?;
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
        self.require_local_port()?;
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
    fn turn(&mut self, id: RecordId) -> StoreResult<Read<StoredEvent>> {
        self.require_local_port()?;
        self.read_turn(id)
    }
    fn native_turn(
        &mut self,
        session: SessionId,
        provider: Provider,
        vendor: &str,
    ) -> StoreResult<Read<StoredEvent>> {
        self.require_local_port()?;
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
        self.require_local_port()?;
        self.read_recent_turns(agent, since, budget)
    }
    fn transcript_events(
        &mut self,
        agent: AgentId,
        session: Option<SessionId>,
        budget: ReadBudget,
    ) -> StoreResult<TranscriptRecords> {
        self.require_local_port()?;
        self.read_transcript_events(agent, session, budget)
    }
    fn turns(&mut self, _agent: AgentId, _budget: ReadBudget) -> StoreResult<Page<StoredEvent>> {
        self.require_local_port()?;
        self.read_turns(_agent, _budget)
    }
    fn conversation_turns(
        &mut self,
        agent: AgentId,
        provider: Provider,
        native_ref: &str,
        budget: ReadBudget,
    ) -> StoreResult<Page<StoredEvent>> {
        self.require_local_port()?;
        self.read_conversation_turns(agent, provider, native_ref, budget)
    }
    fn capture_source(&mut self, _source: RecordId) -> StoreResult<Read<ProjectionRecord>> {
        self.read_capture_source(_source)
    }
    fn capture_outcome(
        &mut self,
        source: RecordId,
        kind: Option<EventKind>,
    ) -> StoreResult<Read<StoredEvent>> {
        self.require_local_port()?;
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
        self.require_local_port()?;
        self.read_processes(budget)
    }
    fn cursor(&mut self, agent: AgentId, purpose: String) -> StoreResult<Read<CursorHead>> {
        self.require_local_port()?;
        self.read_cursor(agent, purpose)
    }
    fn pending_effects(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        self.require_local_port()?;
        self.read_pending_effects(budget)
    }
    fn effect(&mut self, id: RecordId) -> StoreResult<Read<ProjectionRecord>> {
        self.require_local_port()?;
        self.read_effect(id)
    }
    fn integrations(&mut self, budget: ReadBudget) -> StoreResult<Page<ProjectionRecord>> {
        self.require_local_port()?;
        self.read_integrations(budget)
    }
    fn import_progress(
        &mut self,
        import: RecordId,
        budget: ReadBudget,
    ) -> StoreResult<Page<ImportCheckpoint>> {
        self.require_local_port()?;
        self.read_import_progress(import, budget)
    }
}
