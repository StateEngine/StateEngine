//! Plan, release the read pin, await the real writer, then read back the same key.
use super::*;
use se_core::{
    commit::{Cx, OpStep},
    dispatch::Kernel,
};
use se_store::{CommitReceipt, SqliteSnapshot};

pub(super) async fn step<O: Send + 'static, T: Send + 'static>(
    store: &store::Store,
    admission: se_store::Admission,
    deadline: &Deadline,
    plan: impl FnOnce(&Kernel, &mut Cx<'_, SqliteSnapshot>) -> Result<OpStep<O, T>> + Send + 'static,
    finish: impl FnOnce(&Kernel, &mut Cx<'_, SqliteSnapshot>, T, CommitReceipt) -> Result<O>
    + Send
    + 'static,
) -> Result<O> {
    let draft = store
        .read(admission.clone(), deadline, move |cx| {
            plan(&Kernel::new(crate::runtime::start::allocate_facts()?)?, cx)
        })
        .await?;
    match draft {
        OpStep::Complete(value) => Ok(value),
        OpStep::Commit { batch, then } => {
            let receipt = store
                .commit(admission.clone(), deadline, None, move |_, _| Ok(batch))
                .await?;
            store
                .read(admission, deadline, move |cx| {
                    finish(
                        &Kernel::new(crate::runtime::start::allocate_facts()?)?,
                        cx,
                        then,
                        receipt,
                    )
                })
                .await
        }
        OpStep::Custody(never) => match never {},
    }
}
