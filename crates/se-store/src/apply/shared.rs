//! Persist shared-scope and thread-membership facts.
//!
//! The server's native lifetime stays in `processes`; these rows only say which
//! agents are attached to it and how each attachment ended. A scope transition
//! never invents a process state, and a thread end never claims the server
//! stopped.
//!
//! Guards follow one rule: every event about an existing scope is guarded by the
//! **stored scope revision** and writes that revision plus one, because a
//! membership change is a change to the scope (it changes whether the server may
//! stop). The membership row is guarded separately by its own open state, and its
//! own revision is bumped with it.

use super::*;
use se_store_contract::{SharedScopePhase, ThreadEnd};
use se_types::{EventId, LifecycleId, SessionId};

fn phase(value: SharedScopePhase) -> &'static str {
    match value {
        SharedScopePhase::Starting => "starting",
        SharedScopePhase::Live => "live",
        SharedScopePhase::Stopped => "stopped",
        SharedScopePhase::Died => "died",
    }
}

fn parsed(value: &str) -> StoreResult<SharedScopePhase> {
    Ok(match value {
        "starting" => SharedScopePhase::Starting,
        "live" => SharedScopePhase::Live,
        "stopped" => SharedScopePhase::Stopped,
        "died" => SharedScopePhase::Died,
        _ => return Err(invalid("shared scope phase")),
    })
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
        // First registration, then either serving or ending.
        (None, Starting | Live | Stopped | Died)
            | (Some(Starting), Live | Stopped | Died)
            // A live scope that loses its server has died; it was not stopped,
            // and that distinction must never collapse.
            | (Some(Live), Stopped | Died)
    )
}

/// What the stored scope row says, read inside the write transaction.
struct Stored {
    revision: u64,
    phase: SharedScopePhase,
}

fn stored(c: &Connection, p: &[u8], id: &[u8]) -> StoreResult<Option<Stored>> {
    let row: Option<(i64, String)> = c
        .query_row(
            "SELECT revision, phase FROM shared_scope WHERE project_id=? AND scope_id=?",
            rusqlite::params![p, id],
            |r| Ok((crate::sql_value::value(r, 0)?, r.get(1)?)),
        )
        .optional()
        .map_err(sql)?;
    match row {
        None => Ok(None),
        Some((revision, phase)) => Ok(Some(Stored {
            revision: u64::try_from(revision).map_err(invalid)?,
            phase: parsed(&phase)?,
        })),
    }
}

fn open_memberships(c: &Connection, p: &[u8], id: &[u8]) -> StoreResult<u64> {
    let count: i64 = c
        .query_row(
            "SELECT COUNT(*) FROM shared_scope_thread
             WHERE project_id=? AND scope_id=? AND detached_seq IS NULL",
            rusqlite::params![p, id],
            |r| r.get(0),
        )
        .map_err(sql)?;
    u64::try_from(count).map_err(invalid)
}

/// Confirm the caller's declared expected revision is the stored one.
///
/// `Absent` means "no scope yet" and is accepted only when the row truly is
/// absent; every later event must name the exact stored revision.
fn expected_revision(want: Expected, row: Option<&Stored>) -> StoreResult<u64> {
    match (want, row) {
        (Expected::Absent, None) => Ok(0),
        (Expected::Absent, Some(_)) => Err(fail(
            StoreErrorCode::RevisionConflict,
            "a shared scope already exists for this login; name its exact revision",
        )),
        (Expected::Revision(want), Some(row)) if want.value.get() == row.revision => {
            Ok(row.revision)
        }
        (Expected::Revision(_), Some(_)) => Err(fail(
            StoreErrorCode::RevisionConflict,
            "shared scope revision differs from the one read",
        )),
        (Expected::Revision(_), None) => Err(fail(
            StoreErrorCode::RevisionConflict,
            "shared scope is absent; a first registration uses Expected::Absent",
        )),
    }
}

pub(super) fn revision(c: &Connection, event: &NewEvent) -> StoreResult<u64> {
    // The store's own revision dispatch asks this only for the row's next
    // revision; the guards below decide whether the transition is legal.
    let (id, want) = match &event.body {
        EventBody::SharedScopeChanged {
            scope, expected, ..
        }
        | EventBody::ThreadAttached {
            scope, expected, ..
        }
        | EventBody::ThreadDetached {
            scope, expected, ..
        }
        | EventBody::SharedScopeSettled {
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
    authority: &ApplyAuthority<'_>,
) -> StoreResult<()> {
    if authority.lease.mode != LeaseMode::Host {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "shared-scope facts require the owning host writer",
        ));
    }
    let p = project_id(c, &h.scope, false)?;
    match body {
        EventBody::SharedScopeChanged {
            scope,
            login,
            server_process,
            phase: next,
            from,
            expected,
        } => changed(
            c,
            &p,
            scope,
            login,
            server_process,
            *next,
            *from,
            *expected,
            seq,
        ),
        EventBody::ThreadAttached {
            scope,
            session,
            thread,
            expected,
        } => attached(c, &p, scope, session, thread, *expected, seq),
        EventBody::ThreadDetached {
            scope,
            session,
            end: how,
            reason,
            expected,
        } => detached(c, &p, scope, session, *how, reason, *expected, seq),
        EventBody::SharedScopeSettled {
            scope,
            server_process,
            exit_witness,
            reason,
            expected,
        } => settled(
            c,
            &p,
            &scope_key(c, &h.scope, false)?,
            scope,
            server_process,
            exit_witness,
            reason,
            *expected,
            seq,
        ),
        _ => Err(invalid("shared scope apply dispatch")),
    }
}

#[allow(clippy::too_many_arguments)]
fn changed(
    c: &Connection,
    p: &[u8],
    scope: &LifecycleId,
    login: &str,
    server_process: &LifecycleId,
    next: SharedScopePhase,
    from: Option<SharedScopePhase>,
    want: Expected,
    seq: i64,
) -> StoreResult<()> {
    let id = key(c, "lifecycle", scope.as_str(), &[0], true)?;
    let row = stored(c, p, &id)?;
    let revision = expected_revision(want, row.as_ref())?;
    // The claimed prior phase is never trusted: it must be the stored one.
    let prior = row.as_ref().map(|row| row.phase);
    if prior != from {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "shared scope prior phase differs from the stored phase",
        ));
    }
    if !legal(prior, next) {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "shared scope phase change is not a legal transition",
        ));
    }
    if login.is_empty() || login.len() > 4096 {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "shared scope must name the login it serves",
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
    // The scope's server is the host's own process: its immutable fact carries
    // the host binding for exactly this scope, and only the host writes it.
    custody(c, p, &id, &server)?;
    if let Some(row) = &row {
        // Identity is immutable: a different login or server is a new scope.
        let existing: (String, Vec<u8>) = c
            .query_row(
                "SELECT login, server_process FROM shared_scope WHERE project_id=? AND scope_id=?",
                rusqlite::params![p, id],
                |r| Ok((r.get(0)?, crate::sql_value::value(r, 1)?)),
            )
            .map_err(sql)?;
        if existing.0 != login || existing.1 != server {
            return Err(fail(
                StoreErrorCode::InvalidTransition,
                "shared scope login and server identity cannot change; register a new scope",
            ));
        }
        let _ = row.revision;
    }
    // Stopping is the one transition that needs every agent gone first.
    if next == SharedScopePhase::Stopped && open_memberships(c, p, &id)? > 0 {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "a shared scope stops only after its last agent detaches",
        ));
    }
    c.execute(
        "INSERT INTO shared_scope(project_id,scope_id,login,server_process,phase,revision,last_seq)
         VALUES(?,?,?,?,?,?,?)
         ON CONFLICT(project_id,scope_id) DO UPDATE SET
           phase=excluded.phase, revision=excluded.revision, last_seq=excluded.last_seq",
        crate::sql_value::sql_params![p, id, login, server, phase(next), revision + 1, seq],
    )
    .map_err(sql)?;
    Ok(())
}

fn attached(
    c: &Connection,
    p: &[u8],
    scope: &LifecycleId,
    session: &SessionId,
    thread: &str,
    want: Expected,
    seq: i64,
) -> StoreResult<()> {
    if thread.is_empty() || thread.len() > 512 {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "attached thread must name the provider's thread id",
        ));
    }
    let id = key(c, "lifecycle", scope.as_str(), &[0], true)?;
    let row = stored(c, p, &id)?.ok_or_else(|| {
        fail(
            StoreErrorCode::InvalidTransition,
            "an agent attaches only to a registered shared scope",
        )
    })?;
    let revision = expected_revision(want, Some(&row))?;
    if row.phase != SharedScopePhase::Live {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "an agent may attach only to a live shared scope",
        ));
    }
    let target = key(c, "session", session.as_str(), &[0], true)?;
    c.execute(
        "INSERT INTO shared_scope_thread(project_id,scope_id,session_id,thread_id,attached_seq,revision)
         VALUES(?,?,?,?,?,1)",
        crate::sql_value::sql_params![p, id, target, thread, seq],
    )
    .map_err(|error| {
        fail(
            StoreErrorCode::InvalidTransition,
            format!("a session attaches to one thread once: {error}"),
        )
    })?;
    bump(c, p, &id, revision, seq)
}

#[allow(clippy::too_many_arguments)]
fn detached(
    c: &Connection,
    p: &[u8],
    scope: &LifecycleId,
    session: &SessionId,
    how: ThreadEnd,
    reason: &str,
    want: Expected,
    seq: i64,
) -> StoreResult<()> {
    if reason.is_empty() || reason.len() > 1024 {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "a stopped thread says why it ended",
        ));
    }
    let id = key(c, "lifecycle", scope.as_str(), &[0], true)?;
    let row = stored(c, p, &id)?.ok_or_else(|| {
        fail(
            StoreErrorCode::InvalidTransition,
            "a thread detaches only from a registered shared scope",
        )
    })?;
    let revision = expected_revision(want, Some(&row))?;
    let target = key(c, "session", session.as_str(), &[0], true)?;
    // The membership is guarded by its own open state: how a thread ended is
    // recorded once, and a stale row cannot be closed twice.
    let changed = c
        .execute(
            "UPDATE shared_scope_thread
             SET detached_seq=?, detached_reason=?, revision=revision+1
             WHERE project_id=? AND scope_id=? AND session_id=? AND detached_seq IS NULL",
            crate::sql_value::sql_params![seq, end(how), p, id, target],
        )
        .map_err(sql)?;
    if changed != 1 {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "thread detach requires one open membership for this session",
        ));
    }
    bump(c, p, &id, revision, seq)
}

/// Store the scope's next revision for a membership event.
///
/// A membership change changes whether the server may stop, so it is a scope
/// change and must move the scope revision; leaving it alone would let a stale
/// membership event pass the next guard.
fn bump(c: &Connection, p: &[u8], id: &[u8], revision: u64, seq: i64) -> StoreResult<()> {
    let changed = c
        .execute(
            "UPDATE shared_scope SET revision=?, last_seq=? WHERE project_id=? AND scope_id=? AND revision=?",
            crate::sql_value::sql_params![revision + 1, seq, p, id, revision],
        )
        .map_err(sql)?;
    if changed != 1 {
        return Err(fail(
            StoreErrorCode::RevisionConflict,
            "shared scope revision moved while this membership event was applied",
        ));
    }
    Ok(())
}

/// The named server must be host-owned custody bound to this exact scope.
/// The binding names the scope's registry-wide lifecycle key while the scope
/// row uses the project's own key, so the coupling compares the wire ids.
/// A missing or inconsistent binding refuses as unreadable custody.
fn custody(c: &Connection, p: &[u8], scope: &[u8], server: &[u8]) -> StoreResult<()> {
    // The immutable fact's principal, host scope binding and host epoch.
    type Binding = (Option<Vec<u8>>, Option<Vec<u8>>, Option<String>);
    let row: Option<Binding> = c
        .query_row(
            "SELECT d.principal_id,d.host_scope,d.host_epoch
             FROM processes h JOIN process_data d ON d.event_seq=h.first_seq
             WHERE h.project_id=? AND h.process_id=?",
            rusqlite::params![p, server],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(sql)?;
    if let Some((None, Some(bound), Some(_))) = row {
        let project_scope = [&[1u8][..], p].concat();
        let bound_wire = identity::wire(c, "lifecycle", &bound, &[0])?;
        let scope_wire = identity::wire(c, "lifecycle", scope, &project_scope)?;
        if bound_wire == scope_wire {
            return Ok(());
        }
    }
    Err(fail(
        StoreErrorCode::Unreadable,
        "shared scope custody is unreadable: its server is not host-owned for this scope",
    ))
}

/// Startup custody settled the scope: the host proved its server exited, so
/// the scope is died and every open thread ends with the relaunch step, in
/// this one transaction. An unproved observation never reaches this arm.
#[allow(clippy::too_many_arguments)]
fn settled(
    c: &Connection,
    p: &[u8],
    event_scope: &[u8],
    scope: &LifecycleId,
    server_process: &LifecycleId,
    exit_witness: &EventId,
    reason: &str,
    want: Expected,
    seq: i64,
) -> StoreResult<()> {
    if reason.is_empty() || reason.len() > 1024 {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "a settled scope says why it died and how to relaunch",
        ));
    }
    let id = key(c, "lifecycle", scope.as_str(), &[0], true)?;
    let row = stored(c, p, &id)?.ok_or_else(|| {
        fail(
            StoreErrorCode::InvalidTransition,
            "only a registered shared scope can be settled",
        )
    })?;
    let revision = expected_revision(want, Some(&row))?;
    if !matches!(
        row.phase,
        SharedScopePhase::Starting | SharedScopePhase::Live
    ) {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "a stopped or died scope is already settled",
        ));
    }
    let server = key(c, "lifecycle", server_process.as_str(), &[0], false)?;
    let existing: Vec<u8> = c
        .query_row(
            "SELECT server_process FROM shared_scope WHERE project_id=? AND scope_id=?",
            rusqlite::params![p, id],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if existing != server {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "settlement names a different server than the scope records",
        ));
    }
    custody(c, p, &id, &server)?;
    // The witness is this record's own witnessed exit, in this project. The
    // settlement rides the same batch, so the head is already terminal here.
    let witness = key(c, "event", exit_witness.as_str(), event_scope, false)?;
    let witnessed: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM processes h
             JOIN process_data d ON d.event_seq=h.last_seq
             JOIN events e ON e.event_id=?
             WHERE h.project_id=? AND h.process_id=? AND h.last_seq=e.seq AND h.state='exited')",
            rusqlite::params![witness, p, server],
            |r| r.get(0),
        )
        .map_err(sql)?;
    if !witnessed {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "settlement requires the server's witnessed exit as its basis",
        ));
    }
    // Every open thread ends at once, with the relaunch step as its reason.
    c.execute(
        "UPDATE shared_scope_thread
         SET detached_seq=?, detached_reason=?, revision=revision+1
         WHERE project_id=? AND scope_id=? AND detached_seq IS NULL",
        crate::sql_value::sql_params![seq, end(ThreadEnd::ScopeEnded), p, id],
    )
    .map_err(sql)?;
    bump(c, p, &id, revision, seq)?;
    let changed = c
        .execute(
            "UPDATE shared_scope SET phase='died' WHERE project_id=? AND scope_id=? AND revision=?",
            crate::sql_value::sql_params![p, id, revision + 1],
        )
        .map_err(sql)?;
    if changed != 1 {
        return Err(fail(
            StoreErrorCode::RevisionConflict,
            "shared scope revision moved while settlement was applied",
        ));
    }
    Ok(())
}
