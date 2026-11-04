//! Release each scoped read before awaiting a shared writer completion.
use super::*;
use crate::client::lease::Deadline;
use se_core::{
    commit::{Cx, OpStep},
    dispatch::Kernel,
};
use se_store::{CommitReceipt, SqliteSnapshot};

pub(super) async fn run<O: Send + 'static, T: Send + 'static>(
    router: &HostedRouter,
    target: &api::HostSessionTarget,
    generation: api::Generation,
    deadline: &Deadline,
    plan: impl FnOnce(&Kernel, &mut Cx<'_, SqliteSnapshot>) -> Result<OpStep<O, T>> + Send + 'static,
    finish: impl FnOnce(&Kernel, &mut Cx<'_, SqliteSnapshot>, T, CommitReceipt) -> Result<O>
    + Send
    + 'static,
) -> Result<O> {
    let scope = scope(target, generation)?;
    let admission = scope.admission.clone();
    let draft = store::read(router, scope.clone(), deadline, move |read| {
        binding::check(read, &scope, revision())?;
        plan(
            &Kernel::new(crate::runtime::start::allocate_facts()?)?,
            &mut Cx {
                read,
                admission: &admission,
            },
        )
    })
    .await?;
    match draft {
        OpStep::Complete(value) => Ok(value),
        OpStep::Commit { batch, then } => {
            let receipt = store::write(router, batch, "mail.native", deadline).await?;
            let committed = store::known("mail.native", &receipt);
            let scope = super::scope(target, generation)?;
            let admission = scope.admission.clone();
            store::read(router, scope, deadline, move |read| {
                finish(
                    &Kernel::new(crate::runtime::start::allocate_facts()?)?,
                    &mut Cx {
                        read,
                        admission: &admission,
                    },
                    then,
                    receipt,
                )
            })
            .await
            .map_err(|error| committed.response_error(error))
        }
        OpStep::Custody(never) => match never {},
    }
}
