//! Only an earlier linked generation with no launched process is replaceable.
use super::store;
use se_core::{scope, store_error::store_error};
use se_store::{
    Admission, ContainmentFact, EventBody, Expected, InputText, NewEvent, Provider, Revision,
    Snapshot,
};
use se_types::{AgentId, Read, Result, SeError, SessionId};

pub(super) fn previous(
    read: &mut impl Snapshot,
    admission: &Admission,
    agent: AgentId,
) -> Result<Option<(NewEvent, SessionId, Revision)>> {
    let record = match read.latest_session(agent).map_err(|e| store_error(&e))? {
        Read::Present { value } => value,
        Read::Absent { .. } => return Ok(None),
        Read::Unreadable { source, reason, .. } => return Err(scope::unreadable(&source, &reason)),
        Read::Unknown { what } => return Err(scope::unreadable("linked bind target", &what)),
    };
    if !matches!(
        record.current.body,
        EventBody::SessionActivated { .. } | EventBody::SessionPrepared { .. }
    ) {
        return Ok(None);
    }
    let original = record.original.as_deref().unwrap_or(&record.current);
    if let (
        EventBody::SessionPrepared {
            provider: Provider::SeCode,
            generation,
            ..
        },
        EventBody::SessionActivated {
            session,
            process: None,
            containment: ContainmentFact::NotLaunched,
            ..
        },
    ) = (&original.body, &record.current.body)
        && *generation < admission.generation
    {
        // HostedRuntime acquired native ownership of this newer generation.
        // The old grant was process-local and died with its host; there is no
        // child process to terminate or an external bearer to take over.
        let facts = crate::runtime::start::allocate_facts()?;
        return Ok(Some((
            store::event(read, admission, facts.event, facts.occurred_at_us,
                EventBody::SessionRevoked {
                    session: session.clone(),
                    expected: Expected::Revision(record.revision),
                    reason: InputText::Inline("Previous SE Code host generation ended; atomically binding its replacement.".into()),
                }),
            session.clone(),
            record.revision,
        )));
    }
    Err(SeError::invalid(
        "linked bind target",
        "no existing active or prepared session; revoke the previous native binding through Owner control first",
    ))
}
