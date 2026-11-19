//! Coordinate source work with observed checkout locks.
use super::*;

/// Run source work and transfer newly observed checkout-lock state to the same
/// scheduler before it can publish. Callers pair this with `drive_events`.
pub fn drive_quantum(
    controller: &mut crate::atlas_runtime::NativeController<NativeRenewal>,
    duration: Duration,
) -> AtlasResult<Option<WorkReport>> {
    sync_locks(controller)?;
    let result = controller.work_quantum(duration);
    sync_locks(controller)?;
    result
}
pub(super) fn sync_locks(
    controller: &mut crate::atlas_runtime::NativeController<NativeRenewal>,
) -> AtlasResult<usize> {
    let changes: Vec<_> = controller
        .runtime_mut()
        .driver_mut()
        .roots
        .iter_mut()
        .filter_map(|root| root.pending_lock.take().map(|held| (root.id.clone(), held)))
        .collect();
    let count = changes.len();
    for (root, held) in changes {
        controller.git_lock(&root, held)?;
    }
    Ok(count)
}
