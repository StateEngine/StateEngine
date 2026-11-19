//! Shared-scope heads and thread membership on the ordinary snapshot port.
//!
//! These reads answer "who is attached to this login's daemon" from the store
//! rather than from a live census, so startup custody can settle a scope and
//! a stop can know whether the last agent has left.
use super::*;
use se_store_contract::{SharedScope, SharedThread, ThreadEndRecord};

impl SqliteSnapshot {
    pub(super) fn read_shared_scope(
        &self,
        scope: se_types::LifecycleId,
    ) -> StoreResult<Read<SharedScope>> {
        let p = self.project_bytes()?;
        let id = key(&self.db, "lifecycle", scope.as_str(), &[0], false)?;
        let row: Option<(String, Vec<u8>, String, u64, i64)> = self
            .db
            .query_row(
                "SELECT login,server_process,phase,revision,last_seq FROM shared_scope WHERE project_id=? AND scope_id=?",
                rusqlite::params![p, id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, crate::sql_value::value(r, 3)?, r.get(4)?)),
            )
            .optional()
            .map_err(|error| self.read_sql(error))?;
        let Some((login, server, phase, revision, seq)) = row else {
            return Ok(self.absent("shared_scope"));
        };
        Ok(Read::Present {
            value: SharedScope {
                scope,
                login,
                server_process: wire(&self.db, "lifecycle", &server, &[0])?
                    .parse()
                    .map_err(invalid)?,
                phase: parse_phase(&phase)?,
                revision: codec::revision(revision)?,
                last: StorePosition::new_internal(
                    self.info.id.clone(),
                    self.info.incarnation,
                    seq as u64,
                )?,
            },
        })
    }

    pub(super) fn read_shared_threads(
        &self,
        scope: se_types::LifecycleId,
        budget: ReadBudget,
    ) -> StoreResult<Page<SharedThread>> {
        let deadline = query::deadline(&budget)?;
        let p = self.project_bytes()?;
        let id = key(&self.db, "lifecycle", scope.as_str(), &[0], false)?;
        let binding = format!("shared:threads:{}", scope.as_str());
        let (h, after) = self.window(&budget, &binding, true)?;
        let mut q = self
            .db
            .prepare(
                "SELECT session_id,thread_id,attached_seq,detached_seq,detached_reason,revision
                 FROM shared_scope_thread
                 WHERE project_id=? AND scope_id=? AND attached_seq>? AND attached_seq<=?
                 ORDER BY attached_seq LIMIT ?",
            )
            .map_err(|error| self.read_sql(error))?;
        let mut rows = q
            .query(rusqlite::params![
                p,
                id,
                after as i64,
                h as i64,
                i64::from(budget.page.limit.get()) + 1
            ])
            .map_err(|error| self.read_sql(error))?;
        let mut items = Vec::new();
        let mut bytes = 0u64;
        let mut last = after;
        let mut stop = StopReason::Exhausted;
        let mut remaining = None;
        while let Some(row) = rows.next().map_err(|error| self.read_sql(error))? {
            query::check_deadline(deadline)?;
            let member = ThreadRow::read(row).map_err(|error| self.read_sql(error))?;
            if items.len() as u32 >= budget.page.limit.get() {
                stop = StopReason::ItemLimit;
                remaining = Some(1);
                break;
            }
            let cost =
                (member.thread.len() + member.reason.as_deref().map_or(0, str::len) + 128) as u64;
            if bytes + cost > u64::from(budget.page.max_bytes.get()) {
                if items.is_empty() {
                    return Err(query::budget_failure(
                        &budget,
                        cost,
                        "the first thread membership exceeds page bytes",
                    ));
                }
                stop = StopReason::ByteLimit;
                remaining = Some(1);
                break;
            }
            bytes += cost;
            last = member.attached as u64;
            items.push(self.thread(&scope, member)?);
        }
        let observed = Some(self.cursor(&binding, h, last)?);
        let next = if stop != StopReason::Exhausted {
            observed.clone()
        } else {
            None
        };
        let omission = match remaining {
            None => Omission::None,
            Some(count) => Omission::Known {
                count: std::num::NonZeroU64::new(count).ok_or_else(|| invalid("zero remaining"))?,
                reason: if stop == StopReason::ItemLimit {
                    OmissionReason::Limit
                } else {
                    OmissionReason::Budget
                },
            },
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
            end_cursor: observed,
            returned: items.len() as u64,
            limit: budget.page.limit,
            bytes,
            max_bytes: budget.page.max_bytes,
            omitted_before: Omission::None,
            omitted_after: omission,
            unreadable: 0,
            stop_reason: stop,
        })
        .map_err(invalid)?;
        Page::new(items, window, next).map_err(invalid)
    }
}

impl SqliteSnapshot {
    /// One membership row becomes its typed record; a closed row must agree
    /// with the event that closed it.
    fn thread(
        &self,
        scope: &se_types::LifecycleId,
        member: ThreadRow,
    ) -> StoreResult<SharedThread> {
        let s = scope_key(&self.db, &self.scope.admission.scope, false)?;
        let position = |seq: i64| {
            StorePosition::new_internal(self.info.id.clone(), self.info.incarnation, seq as u64)
        };
        let detached = match (member.detached, member.reason) {
            (Some(seq), Some(reason)) => {
                let (end, event_reason) = thread_end(&self.db, seq)?;
                if event_reason != reason {
                    return Err(fail(
                        StoreErrorCode::ProjectionInconsistent,
                        "membership reason differs from its closing event",
                    ));
                }
                Some(ThreadEndRecord {
                    end,
                    at: position(seq)?,
                    reason,
                })
            }
            (None, None) => None,
            _ => {
                return Err(fail(
                    StoreErrorCode::ProjectionInconsistent,
                    "membership end and reason disagree",
                ));
            }
        };
        Ok(SharedThread {
            scope: scope.clone(),
            session: wire(&self.db, "session", &member.session, &s)?
                .parse()
                .map_err(invalid)?,
            thread: member.thread,
            attached: position(member.attached)?,
            detached,
            revision: codec::revision(member.revision)?,
        })
    }
}

/// One stored membership row, before its closing event is consulted.
struct ThreadRow {
    session: Vec<u8>,
    thread: String,
    attached: i64,
    detached: Option<i64>,
    reason: Option<String>,
    revision: u64,
}

impl ThreadRow {
    fn read(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            session: row.get(0)?,
            thread: row.get(1)?,
            attached: row.get(2)?,
            detached: row.get(3)?,
            reason: row.get(4)?,
            revision: crate::sql_value::value(row, 5)?,
        })
    }
}

fn parse_phase(value: &str) -> StoreResult<se_store_contract::SharedScopePhase> {
    use se_store_contract::SharedScopePhase::*;
    Ok(match value {
        "starting" => Starting,
        "live" => Live,
        "stopped" => Stopped,
        "died" => Died,
        _ => return Err(invalid("shared scope phase")),
    })
}

/// The manner a membership ended is the closing event's own fact. A
/// settlement closes every open thread in one event, so each thread keeps
/// the settlement's relaunch step as its reason.
fn thread_end(db: &Connection, seq: i64) -> StoreResult<(se_store_contract::ThreadEnd, String)> {
    let kind: String = db
        .query_row("SELECT kind FROM events WHERE seq=?", [seq], |r| r.get(0))
        .map_err(sql)?;
    let facts = codec::facts(db, seq)?;
    let field = |name: &str| {
        facts
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| invalid("membership closing event lacks its fact"))
    };
    match kind.as_str() {
        "shared.thread_detached" => Ok((
            match field("end")?.as_str() {
                "stopped" => se_store_contract::ThreadEnd::Stopped,
                "scope-ended" => se_store_contract::ThreadEnd::ScopeEnded,
                _ => return Err(invalid("thread end manner")),
            },
            field("reason")?,
        )),
        "shared.settled" => Ok((se_store_contract::ThreadEnd::ScopeEnded, field("reason")?)),
        _ => Err(fail(
            StoreErrorCode::ProjectionInconsistent,
            "membership was closed by an unrelated event",
        )),
    }
}
