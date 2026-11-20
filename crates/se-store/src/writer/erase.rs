//! Erasure runs on the authoritative writer between commit groups, under its
//! lease, so no other commit interleaves with the request and its cleanup.
use super::*;
pub(super) enum EraseRequest {
    Plan(Vec<se_types::EventId>, Reply<ErasurePlan>),
    Run(ErasurePlan, ErasureApproval, Reply<ErasureReport>),
}
impl SqliteClient {
    /// Plans under the writer's own lease at each event's committed revision;
    /// reads only, and changes nothing.
    pub fn erasure_plan(
        &self,
        events: Vec<se_types::EventId>,
    ) -> StoreResult<Completion<ErasurePlan>> {
        let (reply, wait) = completion::channel();
        self.send_erasure(EraseRequest::Plan(events, reply))?;
        Ok(wait)
    }
    pub fn erase(
        &self,
        plan: ErasurePlan,
        approval: ErasureApproval,
    ) -> StoreResult<Completion<ErasureReport>> {
        let (reply, wait) = completion::channel();
        self.send_erasure(EraseRequest::Run(plan, approval, reply))?;
        Ok(wait)
    }
    fn send_erasure(&self, request: EraseRequest) -> StoreResult<()> {
        let mut admission = self
            .shared
            .admission
            .lock()
            .map_err(|_| fail(StoreErrorCode::WriterClosed, "writer admission poisoned"))?;
        if admission.closed || admission.recovering {
            return Err(fail(
                StoreErrorCode::WriterClosed,
                "the writer is draining or recovering; nothing was erased",
            ));
        }
        if admission.requests == self.shared.request_limit {
            return Err(fail(
                StoreErrorCode::Backpressure,
                "writer request bound reached; nothing was erased",
            ));
        }
        self.sender
            .try_send(Command::Erase(Box::new(request)))
            .map_err(|e| {
                fail(
                    match e {
                        TrySendError::Full(_) => StoreErrorCode::Backpressure,
                        TrySendError::Disconnected(_) => StoreErrorCode::WriterClosed,
                    },
                    "writer did not accept the erasure; nothing was erased",
                )
            })?;
        admission.requests += 1;
        Ok(())
    }
}
pub(super) fn execute(
    host: &mut SqliteHost,
    lease: &dyn RuntimeLease,
    shared: &Shared,
    request: Box<EraseRequest>,
) -> StoreResult<()> {
    let result = match *request {
        EraseRequest::Plan(events, reply) => {
            let planned = crate::erasure::options(host)
                .and_then(|options| crate::erasure::plan_events(&options, events, lease));
            shared.completed(0)?;
            reply.send(planned);
            return Ok(());
        }
        EraseRequest::Run(plan, approval, reply) => {
            (crate::erasure::erase(host, plan, approval, lease), reply)
        }
    };
    let (result, reply) = result;
    if result
        .as_ref()
        .is_err_and(|e| e.code == StoreErrorCode::CommitOutcomeUnknown)
    {
        host.engine.poisoned = true;
    }
    shared.completed(0)?;
    shared
        .admission
        .lock()
        .map_err(|_| fail(StoreErrorCode::WriterClosed, "writer admission poisoned"))?
        .recovering = host.engine.poisoned;
    reply.send(result);
    Ok(())
}
