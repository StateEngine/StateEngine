//! Bounded reads for a session's continuity packet: the newest turns, the
//! captured turns. No full-history scan.
use super::*;
impl SqliteSnapshot {
    /// The newest turns after `since`, oldest first, with the older turns
    /// this bounded tail left out counted exactly in `omitted_before`.
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    pub(super) fn read_recent_turns(
        &mut self,
        agent: AgentId,
        since: Option<StorePosition>,
        budget: ReadBudget,
    ) -> StoreResult<Page<StoredEvent>> {
        let deadline = query::deadline(&budget)?;
        if budget.page.after.is_some() {
            return Err(fail(
                StoreErrorCode::CursorInvalid,
                "recent turns take a since position, never a page continuation",
            ));
        }
        let p = self.project_bytes()?;
        let a = self.agent_bytes(&agent)?;
        let binding = format!("history:recent-turns:{}", agent.as_str());
        let (h, _) = self.window(&budget, &binding, false)?;
        let floor = match &since {
            None => 0,
            Some(position) if position.belongs(&self.info) && position.sequence() <= h => {
                position.sequence()
            }
            Some(_) => {
                return Err(fail(
                    StoreErrorCode::CursorStale,
                    "since position is outside this store, incarnation or snapshot",
                ));
            }
        };
        let params = |extra: i64| {
            vec![
                rusqlite::types::Value::Blob(p.clone()),
                rusqlite::types::Value::Blob(a.clone()),
                rusqlite::types::Value::Integer(floor as i64),
                rusqlite::types::Value::Integer(h as i64),
                rusqlite::types::Value::Integer(extra),
            ]
        };
        let rows = self.query_seqs_before(
            "SELECT e.entity_revision,t.event_seq,t.event_seq FROM turn_data t INDEXED BY turn_data_agent_seq JOIN events e ON e.seq=t.event_seq WHERE NOT (t.role='system' AND t.vendor_ref LIKE 'se.notice.v1/%') AND t.project_id=? AND t.agent_id=? AND t.event_seq>? AND t.event_seq<=? ORDER BY t.event_seq DESC LIMIT ?",
            params(i64::from(budget.page.limit.get())),
            deadline,
        )?;
        let mut items = Vec::new();
        let mut bytes = 0u64;
        let mut stop = StopReason::Exhausted;
        for (_, seq, _) in rows {
            query::check_deadline(deadline)?;
            let e = self.record(seq)?;
            let cost = query::event_size(&e)?;
            if bytes + cost > u64::from(budget.page.max_bytes.get()) {
                if items.is_empty() {
                    return Err(query::budget_failure(
                        &budget,
                        cost,
                        "the newest turn exceeds page bytes",
                    ));
                }
                stop = StopReason::ByteLimit;
                break;
            }
            bytes += cost;
            items.push((seq, e));
        }
        items.reverse();
        let oldest = items.first().map(|(seq, _)| *seq as u64);
        let newest = items.last().map(|(seq, _)| *seq as u64).unwrap_or(floor);
        // Exact count of the older turns the tail left out, from the same index.
        let older: u64 = match oldest {
            None => 0,
            Some(oldest) => {
                let counts = self.query_seqs_before(
                    "SELECT 1,count(*),1 FROM turn_data INDEXED BY turn_data_agent_seq WHERE NOT (role='system' AND vendor_ref LIKE 'se.notice.v1/%') AND project_id=? AND agent_id=? AND event_seq>? AND event_seq<?",
                    vec![rusqlite::types::Value::Blob(p), rusqlite::types::Value::Blob(a),
                        rusqlite::types::Value::Integer(floor as i64), rusqlite::types::Value::Integer(oldest as i64)], deadline)?;
                u64::try_from(
                    counts
                        .first()
                        .ok_or_else(|| invalid("recent-turn count absent"))?
                        .1,
                )
                .map_err(invalid)?
            }
        };
        let omitted_before = match std::num::NonZeroU64::new(older) {
            None => Omission::None,
            Some(count) => {
                if stop == StopReason::Exhausted {
                    stop = StopReason::ItemLimit;
                }
                Omission::Known {
                    count,
                    reason: if stop == StopReason::ByteLimit {
                        OmissionReason::Budget
                    } else {
                        OmissionReason::Limit
                    },
                }
            }
        };
        query::check_deadline(deadline)?;
        let window = Window::new(WindowFields {
            source: Source::Store {
                store: self.info.id.clone(),
                project: match &self.scope.admission.scope {
                    Scope::Project(p) => Some(p.clone()),
                    _ => None,
                },
            },
            from: Sequence::new(floor).map_err(invalid)?,
            to: Sequence::new(h).map_err(invalid)?,
            start_cursor: None,
            end_cursor: Some(SqliteSnapshot::cursor(self, &binding, h, newest)?),
            returned: items.len() as u64,
            limit: budget.page.limit,
            bytes,
            max_bytes: budget.page.max_bytes,
            omitted_before,
            omitted_after: Omission::None,
            unreadable: 0,
            stop_reason: stop,
        })
        .map_err(invalid)?;
        Page::new(items.into_iter().map(|(_, e)| e).collect(), window, None).map_err(invalid)
    }
}

impl SqliteSnapshot {
    pub(super) fn read_resume_head(&mut self, principal: Actor) -> StoreResult<Read<ResumeHead>> {
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
}
