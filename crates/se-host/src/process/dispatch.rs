//! The shared host executor dispatches only typed, already admitted plans.
use super::*;
use crate::{CustodyExecutor, HostFuture, client::lease::Deadline};
use se_core::{ops::AnyOutput, ports::CustodyPlan};
use se_store::Admission;
impl CustodyExecutor for Arc<LaunchCoordinator> {
    fn shutdown<'a>(&'a self, deadline: &'a Deadline) -> HostFuture<'a, crate::CustodyShutdown> {
        Box::pin(async move {
            let report = LaunchCoordinator::shutdown(self, deadline).await?;
            Ok(crate::CustodyShutdown {
                complete: report.complete,
                pending: report.pending,
            })
        })
    }
    fn execute<'a>(
        &'a self,
        plan: CustodyPlan,
        admission: Admission,
        deadline: &'a Deadline,
    ) -> HostFuture<'a, AnyOutput> {
        Box::pin(async move {
            match plan {
                CustodyPlan::Launch(plan) => self
                    .launch(*plan, admission, deadline)
                    .await
                    .map(AnyOutput::from),
                CustodyPlan::Stop(plan) => self
                    .stop(*plan, admission, deadline)
                    .await
                    .map(AnyOutput::from),
                CustodyPlan::Remove(plan) => self
                    .remove(*plan, admission, deadline)
                    .await
                    .map(AnyOutput::from),
                _ => Err(se_core::scope::unreadable(
                    "native process operation",
                    "this plan belongs to the owner runtime, installer or trusted hook adapter",
                )),
            }
        })
    }
}
