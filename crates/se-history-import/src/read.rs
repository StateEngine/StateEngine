//! All read handles end inside this synchronous job, before native IO or await.
use super::Context;
use se_core::scope;
use se_store::{Admission, SqliteSnapshot};
use se_types::Result;
pub(super) fn snapshot<T>(
    context: &Context,
    admission: &Admission,
    read: impl FnOnce(&mut SqliteSnapshot) -> Result<T>,
) -> Result<T> {
    let mut value = None;
    context.snapshot(
        admission,
        Box::new(|snapshot| {
            value = Some(read(snapshot)?);
            Ok(())
        }),
    )?;
    value.ok_or_else(|| scope::unreadable("import read", "the read pin closed without reading"))
}
