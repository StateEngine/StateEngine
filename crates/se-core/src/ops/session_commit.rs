//! Shared session event planning for managed C1/C3 and embedded first bind.
//! Callers supply admitted facts and allocated IDs; there is no clock, RNG,
//! credential generation, native effect or second store submission path here.
use crate::{commit::Cx, dispatch::Kernel, scope};
use se_store::{
    AtomicBatch, Consent, ContainmentFact, EventBody, Expected, InputText, Provider, Revision,
    Snapshot,
};
use se_types::{AgentId, EventId, IdempotencyKey, LifecycleId, Result, SessionId};

pub struct SessionPreparation {
    pub session: SessionId,
    pub agent: AgentId,
    pub provider: Provider,
    pub native_ref: String,
    pub consent: Consent,
    pub generation: u64,
    pub expected: Expected,
}
pub struct SessionActivation {
    pub session: SessionId,
    pub expected: Expected,
    pub incumbent: Option<(SessionId, Revision)>,
    pub process: Option<LifecycleId>,
    pub containment: ContainmentFact,
    pub witnesses: Vec<EventId>,
}
pub fn prepare(input: SessionPreparation) -> Result<EventBody<InputText>> {
    if input.native_ref.is_empty() || input.native_ref.len() > 32768 || input.generation == 0 {
        return Err(se_types::SeError::invalid(
            "session preparation",
            "a nonempty bounded provider conversation and current nonzero generation",
        ));
    }
    Ok(EventBody::SessionPrepared {
        session: input.session,
        agent: input.agent,
        provider: input.provider,
        native_ref: input.native_ref,
        consent: input.consent,
        generation: input.generation,
        expected: input.expected,
    })
}
pub fn activate(input: SessionActivation) -> Result<EventBody<InputText>> {
    if input.witnesses.len() > 16
        || (input.process.is_none() && !matches!(input.containment, ContainmentFact::NotLaunched))
    {
        return Err(se_types::SeError::invalid(
            "session activation",
            "at most sixteen witnesses; a process-free embedded bind has no native containment",
        ));
    }
    Ok(EventBody::SessionActivated {
        session: input.session,
        expected: input.expected,
        incumbent: input.incumbent,
        process: input.process,
        containment: input.containment,
        witnesses: input.witnesses,
    })
}
/// Embedded native sessions prepare and activate together and mint no machine
/// credential. The ordinary executor owns pending-write tracking/submission.
/// Managed process launch reuses prepare/activate on opposite sides of native
/// exec/readiness and includes its credentials in its own C1/C3 batches.
pub fn bind<R: Snapshot>(
    kernel: &Kernel,
    key: IdempotencyKey,
    prepared: SessionPreparation,
    activated: SessionActivation,
    cx: &Cx<'_, R>,
) -> Result<AtomicBatch> {
    if prepared.provider != Provider::SeCode
        || prepared.session != activated.session
        || prepared.generation != cx.admission.generation
        || activated.process.is_some()
    {
        return Err(se_types::SeError::invalid(
            "embedded session binding",
            "one SE Code session under the admitted generation, without process or credential issuance",
        ));
    }
    let intent = serde_json::json!({"agent":prepared.agent,"provider":"secode","session":prepared.session,"native_ref":prepared.native_ref,"consent":prepared.consent,"incumbent":activated.incumbent});
    scope::project(cx.admission)?;
    super::process_commit::batch(
        kernel,
        "session.bind",
        key,
        intent,
        vec![prepare(prepared)?, activate(activated)?],
        cx,
    )
}
