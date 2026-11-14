//! Use the existing writer and retained ordinary-mail completion observer.
use super::*;
use se_store::{
    AtomicBatch, EventBody, EventHeader, IntentDigest, NewEvent, ReadStore, RequestIdentity,
};
use sha2::{Digest, Sha256};

pub(super) async fn commit(
    context: &ExecutionContext,
    admission: Admission,
    key: IdempotencyKey,
    operation: &'static str,
    intent: serde_json::Value,
    bodies: Vec<EventBody<se_store::InputText>>,
) -> Result<se_store::CommitReceipt> {
    let reader = context.reader.clone();
    let info = context
        .blocking
        .run_owned(&session::control::deadline()?, move || {
            reader.info().map_err(|e| store_error(&e))
        })
        .await?;
    let now = session::now()?;
    let events = bodies
        .into_iter()
        .map(|body| {
            Ok(NewEvent {
                header: EventHeader {
                    event: session::event_id(now)?,
                    scope: admission.scope.clone(),
                    actor: admission.actor.clone(),
                    session: admission.session.clone(),
                    origin: info.id.clone(),
                    door: se_store::Door::Host,
                    occurred_at_us: now,
                    cause: None,
                    supersedes: None,
                },
                body,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let digest = Sha256::digest(serde_json::to_vec(&intent).map_err(|_| poisoned())?).into();
    let batch = AtomicBatch {
        admission,
        expected_incarnation: info.incarnation,
        events,
        import_checkpoint: None,
        request: Some(RequestIdentity {
            key: key.clone(),
            intent: IntentDigest {
                operation,
                codec_version: 1,
                sha256: digest,
            },
        }),
    };
    let identity = crate::runtime::WriteIdentity {
        operation,
        key: Some(key),
        natural_key: None,
        natural_events: Vec::new(),
    };
    crate::runtime::submit::submit(context, batch, &identity, &session::control::deadline()?).await
}
