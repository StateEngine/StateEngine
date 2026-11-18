//! Persist shared-scope and thread-membership facts.
//!
//! The server's native lifetime stays in `processes`; these rows only say which
//! agents are attached to it and how each attachment ended. A scope transition
//! never invents a process state, and a thread end never claims the server
//! stopped.

use super::*;
use se_store_contract::{SharedScopePhase, ThreadEnd};
use se_types::{LifecycleId, SessionId};

/// Every write here is the owning host's: a shared scope is process custody, and
/// an ordinary reader must never be able to claim a daemon is live or stopped.
fn host(authority: &ApplyAuthority<'_>) -> StoreResult<()> {
    if authority.lease.mode != LeaseMode::Host {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "shared-scope facts require the owning host writer",
        ));
    }
    Ok(())
}

fn phase(value: SharedScopePhase) -> &'static str {
    match value {
        SharedScopePhase::Starting => "starting",
        SharedScopePhase::Live => "live",
        SharedScopePhase::Stopped => "stopped",
        SharedScopePhase::Died => "died",
    }
}

fn end(value: ThreadEnd) -> &'static str {
    match value {
        ThreadEnd::Stopped => "stopped",
        ThreadEnd::ScopeEnded => "scope-ended",
    }
}

fn legal(from: Option<SharedScopePhase>, to: SharedScopePhase) -> bool {
    use SharedScopePhase::*;
    matches!(
        (from, to),
        // A scope is registered once, then either serves agents or ends.
        (None, Starting | Live | Stopped | Died)
            | (Some(Starting), Live | Stopped | Died)
            // A live scope that loses its server has died; it was not stopped,
            // and this is the only state that must never read as a clean stop.
            | (Some(Live), Stopped | Died)
    )
}

pub(super) fn revision(c: &Connection, event: &NewEvent) -> StoreResult<u64> {
    let (id, want) = match &event.body {
        EventBody::SharedScopeChanged {
            scope, expected, ..
        }
        | EventBody::ThreadAttached {
            scope, expected, ..
        }
        | EventBody::ThreadDetached {
            scope, expected, ..
        } => (scope, *expected),
        _ => return Err(invalid("shared scope revision dispatch")),
    };
    let p = project_id(c, &event.header.scope, false)?;
    let key = key(c, "lifecycle", id.as_str(), &[0], false)?;
    expected(
        c,
        "shared_scope",
        "project_id=? AND scope_id=?",
        &[&p, &key],
        want,
    )
}

pub(super) fn apply(
    c: &Connection,
    h: &EventHeader,
    body: &EventBody<InputText>,
    seq: i64,
    rev: u64,
    authority: &ApplyAuthority<'_>,
) -> StoreResult<()> {
    host(authority)?;
    let p = project_id(c, &h.scope, false)?;
    let write = Write { c, p, seq, rev };
    match body {
        EventBody::SharedScopeChanged {
            scope,
            login,
            server_process,
            phase: next,
            from,
            expected,
            ..
        } => scope_changed(&write, scope, login, server_process, *next, *from, expected),
        EventBody::ThreadAttached {
            scope,
            session,
            thread,
            expected,
            ..
        } => attached(&write, scope, session, thread, expected),
        EventBody::ThreadDetached {
            scope,
            session,
            end: how,
            reason,
            expected,
            ..
        } => detached(&write, scope, session, *how, reason, expected),
        _ => Err(invalid("shared scope apply dispatch")),
    }
}

/// What every branch needs: the connection, the project, and this event's place.
struct Write<'a> {
    c: &'a Connection,
    p: Vec<u8>,
    seq: i64,
    rev: u64,
}

fn scope_changed(
    write: &Write<'_>,
    scope: &LifecycleId,
    login: &str,
    server_process: &LifecycleId,
    next: SharedScopePhase,
    from: Option<SharedScopePhase>,
    expected_value: &Expected,
) -> StoreResult<()> {
    let Write { c, p, seq, rev } = write;
    let Expected::Revision(_) = expected_value else {
        return Err(invalid("shared scope requires an exact revision"));
    };
    if login.is_empty() || login.len() > 4096 {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "shared scope must name the login it serves",
        ));
    }
    if !legal(from, next) {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "shared scope phase change is not a legal transition",
        ));
    }
    let server = key(c, "lifecycle", server_process.as_str(), &[0], true)?;
    let exists: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM processes WHERE project_id=? AND process_id=?)",
            rusqlite::params![p, server],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if !exists {
        return Err(fail(
            StoreErrorCode::ReferenceMissing,
            "shared scope names a server process that is not recorded",
        ));
    }
    let id = key(c, "lifecycle", scope.as_str(), &[0], true)?;
    c.execute(
        "INSERT INTO shared_scope(project_id,scope_id,login,server_process,phase,revision,last_seq)
         VALUES(?,?,?,?,?,?,?)
         ON CONFLICT(project_id,scope_id) DO UPDATE SET
           login=excluded.login, server_process=excluded.server_process,
           phase=excluded.phase, revision=excluded.revision, last_seq=excluded.last_seq",
        crate::sql_value::sql_params![p, id, login, server, phase(next), rev, seq],
    )
    .map_err(sql)?;
    Ok(())
}

fn attached(
    write: &Write<'_>,
    scope: &LifecycleId,
    session: &SessionId,
    thread: &str,
    expected_value: &Expected,
) -> StoreResult<()> {
    let Write { c, p, seq, rev } = write;
    let Expected::Revision(_) = expected_value else {
        return Err(invalid("thread attach requires an exact revision"));
    };
    if thread.is_empty() || thread.len() > 512 {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "attached thread must name the provider's thread id",
        ));
    }
    let id = key(c, "lifecycle", scope.as_str(), &[0], true)?;
    let scoped: Option<String> = c
        .query_row(
            "SELECT phase FROM shared_scope WHERE project_id=? AND scope_id=?",
            rusqlite::params![p, id],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    // Only a live scope accepts an agent: attaching to a starting or ended scope
    // would leave an agent waiting on a server that is not serving anyone.
    if scoped.as_deref() != Some("live") {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "an agent may attach only to a live shared scope",
        ));
    }
    let target = key(c, "session", session.as_str(), &[0], true)?;
    c.execute(
        "INSERT INTO shared_scope_thread(project_id,scope_id,session_id,thread_id,attached_seq,revision)
         VALUES(?,?,?,?,?,?)",
        crate::sql_value::sql_params![p, id, target, thread, seq, rev],
    )
    .map_err(|error| {
        fail(
            StoreErrorCode::InvalidTransition,
            format!("a session attaches to one thread once: {error}"),
        )
    })?;
    Ok(())
}

fn detached(
    write: &Write<'_>,
    scope: &LifecycleId,
    session: &SessionId,
    how: ThreadEnd,
    reason: &str,
    expected_value: &Expected,
) -> StoreResult<()> {
    let Write { c, p, seq, rev } = write;
    let Expected::Revision(_) = expected_value else {
        return Err(invalid("thread detach requires an exact revision"));
    };
    if reason.is_empty() || reason.len() > 1024 {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "a stopped thread says why it ended",
        ));
    }
    let id = key(c, "lifecycle", scope.as_str(), &[0], true)?;
    let target = key(c, "session", session.as_str(), &[0], true)?;
    let changed = c
        .execute(
            "UPDATE shared_scope_thread
             SET detached_seq=?, detached_reason=?, revision=?
             WHERE project_id=? AND scope_id=? AND session_id=? AND detached_seq IS NULL",
            crate::sql_value::sql_params![seq, end(how), rev, p, id, target],
        )
        .map_err(sql)?;
    // A repeated detach is a contradiction, not an idempotent success: the first
    // one already said how this thread ended.
    if changed != 1 {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "thread detach requires one open membership for this session",
        ));
    }
    Ok(())
}
