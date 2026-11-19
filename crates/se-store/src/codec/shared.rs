//! Decode shared-scope event bodies written by `apply/shared.rs`.
//!
//! Every event has this read arm in the same change as its write arm: a receipt
//! is only returned after the event decodes, so an event that cannot be read back
//! must never be committed.

use super::*;

pub(crate) fn body(c: &Connection, seq: i64, kind: &str) -> StoreResult<EventBody<StoredText>> {
    let facts = facts(c, seq)?;
    Ok(match kind {
        "shared.scope" => EventBody::SharedScopeChanged {
            scope: field(&facts, "scope")?,
            login: field(&facts, "login")?,
            server_process: field(&facts, "server_process")?,
            phase: field(&facts, "phase")?,
            from: field(&facts, "from")?,
            expected: field(&facts, "expected")?,
        },
        "shared.thread_attached" => EventBody::ThreadAttached {
            scope: field(&facts, "scope")?,
            session: field(&facts, "session")?,
            thread: field(&facts, "thread")?,
            expected: field(&facts, "expected")?,
        },
        "shared.thread_detached" => EventBody::ThreadDetached {
            scope: field(&facts, "scope")?,
            session: field(&facts, "session")?,
            end: field(&facts, "end")?,
            reason: field(&facts, "reason")?,
            expected: field(&facts, "expected")?,
        },
        "shared.settled" => EventBody::SharedScopeSettled {
            scope: field(&facts, "scope")?,
            server_process: field(&facts, "server_process")?,
            exit_witness: field(&facts, "exit_witness")?,
            reason: field(&facts, "reason")?,
            expected: field(&facts, "expected")?,
        },
        _ => return Err(invalid("shared scope event kind")),
    })
}
