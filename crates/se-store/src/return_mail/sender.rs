//! Message-bound return-mail provenance after ordinary visibility admission.
use super::*;
pub(crate) fn sender(
    db: &Connection,
    admission: &Admission,
    message: &se_types::Read<MessageRecord>,
) -> StoreResult<Option<se_types::remote::RemoteAgentAddress>> {
    let se_types::Read::Present { value: message } = message else {
        return Err(inconsistent());
    };
    let Scope::Project(project) = &admission.scope else {
        return Err(inconsistent());
    };
    let project = crate::identity::key(db, "project", project.as_str(), &[0], false)?;
    let scope = crate::identity::scope_key(db, &admission.scope, false)?;
    let id = crate::identity::key(db, "message", message.message.as_str(), &scope, false)?;
    let facts: Option<String> = db
        .query_row(
            "SELECT facts FROM remote_return_attribution WHERE project_id=? AND message_id=?",
            rusqlite::params![project, id],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    let Some(facts) = facts else { return Ok(None) };
    let record: ReturnAttribution = serde_json::from_str(&facts).map_err(|_| inconsistent())?;
    if message.sender != Actor::Remote(record.principal.clone())
        || message.recipient != Actor::Agent(record.source.agent.clone())
        || admission.scope != Scope::Project(record.source.project.clone())
        || record.message != message.message
    {
        return Err(inconsistent());
    }
    Ok(Some(record.sender))
}
fn inconsistent() -> Box<StoreError> {
    fail(
        StoreErrorCode::ProjectionInconsistent,
        "remote mail provenance differs from its committed message or grant",
    )
}
