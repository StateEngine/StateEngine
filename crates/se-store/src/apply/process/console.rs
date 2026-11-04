//! A console joins a backend only while the original root is still pre-exec.
//! The host records its final argv once, without replacing any native custody.
use super::*;

pub(super) fn argv(
    c: &Connection,
    previous: i64,
    edge: (ProcessState, ProcessState),
    old: &ProcessIdentityRecord,
    new: &ProcessIdentityRecord,
    outcome: Option<&str>,
) -> StoreResult<bool> {
    if edge != (ProcessState::Starting, ProcessState::Starting)
        || outcome != Some("console-prepared")
        || old.root_identity != RootIdentityState::Identified
        || new.root_identity != RootIdentityState::Identified
        || old.custody.format_version != new.custody.format_version
        || old.custody.record != new.custody.record
    {
        return Ok(false);
    }
    let (RecordedIdentity::Present(a), RecordedIdentity::Present(b)) =
        (&old.instance, &new.instance)
    else {
        return Ok(false);
    };
    let (a, b) = (a.fields(), b.fields());
    if a.machine != b.machine
        || a.boot != b.boot
        || a.pid != b.pid
        || a.started != b.started
        || a.executable != b.executable
        || a.argv_sha256 == b.argv_sha256
    {
        return Ok(false);
    }
    // The preceding root publication is required. A second console rebind or
    // a directly registered Starting process cannot reopen this permission.
    Ok(codec::facts(c, previous)?
        .get("outcome")
        .and_then(serde_json::Value::as_str)
        == Some("root-prepared"))
}
