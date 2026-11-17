//! Per-file cooperative CPU limit inside the contained cold worker.
use super::*;
use std::cell::Cell;
thread_local! { static FILE_START: Cell<Option<Duration>> = const { Cell::new(None) }; }

pub(super) fn start() -> AtlasResult<()> {
    let now = se_proc::atlas_worker::current_cpu_time().map_err(failure)?;
    FILE_START.set(Some(now));
    Ok(())
}
pub(super) fn check() -> AtlasResult<()> {
    let Some(start) = FILE_START.get() else {
        return Ok(());
    };
    let current = se_proc::atlas_worker::current_cpu_time().map_err(failure)?;
    let elapsed = current
        .checked_sub(start)
        .ok_or_else(|| failure("worker CPU clock moved backwards"))?;
    if elapsed >= parse_budget().max_work {
        Err(crate::atlas_parse::cpu_expired(parse_budget().max_work))
    } else {
        Ok(())
    }
}
pub(super) fn is_limit(error: &SeError) -> bool {
    matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(detail) if detail.op == "Atlas parse CPU")
}
