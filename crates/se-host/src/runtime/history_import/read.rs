//! All read handles end inside this synchronous job, before native IO or await.
use super::super::{ExecutionContext, executor};
use se_core::{admission::read_scope, store_error::store_error};
use se_store::{Admission, ReadStore, Snapshot, SqliteSnapshot};
use se_types::Result;
pub(super) fn snapshot<T>(
    context: &ExecutionContext,
    admission: &Admission,
    read: impl FnOnce(&mut SqliteSnapshot) -> Result<T>,
) -> Result<T> {
    executor::check_generation(&context.reader, context.generation)?;
    let mut snapshot = context
        .reader
        .snapshot(read_scope(admission))
        .map_err(|e| store_error(&e))?;
    let result = read(&mut snapshot);
    executor::close_read(result, snapshot.close())
}
