//! Private cursor work shares the authoritative writer's queue, barriers and lease.
use super::*;
use crate::atlas_resume::{AtlasResumeMutation, AtlasResumeWrite};
pub(super) struct AtlasRequest {
    mutation: AtlasResumeMutation,
    reply: Reply<AtlasResumeWrite>,
    bytes: usize,
}
impl SqliteClient {
    pub fn atlas_resume(
        &self,
        mutation: AtlasResumeMutation,
    ) -> StoreResult<Completion<AtlasResumeWrite>> {
        let bytes = mutation.bytes()?;
        let mut admission = self
            .shared
            .admission
            .lock()
            .map_err(|_| fail(StoreErrorCode::WriterClosed, "writer admission poisoned"))?;
        if admission.closed || admission.recovering {
            return Err(fail(
                StoreErrorCode::WriterClosed,
                "Atlas cursor writer is draining or recovering",
            ));
        }
        let next = admission
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| invalid("Atlas cursor queue accounting overflow"))?;
        if next > self.shared.byte_limit || admission.requests == self.shared.request_limit {
            return Err(fail(
                StoreErrorCode::Backpressure,
                "writer request/resident byte bound reached",
            ));
        }
        let (reply, wait) = completion::channel();
        self.sender
            .try_send(Command::Atlas(AtlasRequest {
                mutation,
                reply,
                bytes,
            }))
            .map_err(|e| {
                fail(
                    match e {
                        TrySendError::Full(_) => StoreErrorCode::Backpressure,
                        TrySendError::Disconnected(_) => StoreErrorCode::WriterClosed,
                    },
                    "writer did not accept Atlas cursor work",
                )
            })?;
        admission.bytes = next;
        admission.requests += 1;
        Ok(wait)
    }
}
pub(super) fn execute(
    host: &mut SqliteHost,
    lease: &dyn RuntimeLease,
    shared: &Shared,
    request: AtlasRequest,
) -> StoreResult<()> {
    let result = host
        .engine
        .reopen(&host.reader.path, host.reader.timeout, lease)
        .and_then(|_| connection::info(&host.engine.db))
        .and_then(|info| connection::validate_lease(&info, lease, LeaseMode::Host))
        .and_then(|identity| {
            if identity.generation != host.engine.identity.generation {
                return Err(fail(
                    StoreErrorCode::GenerationChanged,
                    "Atlas cursor writer lease changed",
                ));
            }
            host.engine
                .db
                .pragma_update(None, "synchronous", "FULL")
                .map_err(sql)?;
            let result =
                crate::atlas_resume::apply(&host.engine.db, request.mutation, identity.generation);
            if result
                .as_ref()
                .is_err_and(|e| e.code == StoreErrorCode::CommitOutcomeUnknown)
            {
                host.engine.poisoned = true;
            }
            result
        });
    shared.completed(request.bytes)?;
    shared
        .admission
        .lock()
        .map_err(|_| fail(StoreErrorCode::WriterClosed, "writer admission poisoned"))?
        .recovering = host.engine.poisoned;
    request.reply.send(result);
    Ok(())
}
