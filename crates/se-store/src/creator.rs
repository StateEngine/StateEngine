//! Creator control: the current can-create grant plus the immutable direct
//! created_by relation, read together inside one transaction or snapshot.
use crate::{codec, error::*, identity::*, *};
use rusqlite::{Connection, OptionalExtension};
use se_types::AgentId;

/// Refuse unless `creator` holds its current can-create grant and directly
/// created `target` (a stored principal key in project `project`). Imported
/// agents with no recorded creator, grandchildren and other agents' helpers
/// refuse; the grant is checked first so a revoked creator learns that cause.
pub(crate) fn require(
    c: &Connection,
    project: &[u8],
    scope: &[u8],
    creator: &AgentId,
    target: &[u8],
) -> StoreResult<()> {
    let creator_key = key(c, "agent", creator.as_str(), scope, false)?;
    let grant = codec::encode(&GrantKey::AgentCanCreate(creator.clone()))?;
    let granted: Option<bool> = c
        .query_row(
            "SELECT active FROM grants WHERE scope_key=? AND principal_id=? AND grant_key=?",
            rusqlite::params![scope, creator_key, grant],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    if granted != Some(true) {
        return Err(fail(
            StoreErrorCode::CreatorControlRefused,
            "creator lacks its current can-create grant; use owner control",
        ));
    }
    let created_by: Option<Option<Vec<u8>>> = c
        .query_row(
            "SELECT created_by FROM principals WHERE project_id=? AND principal_id=? AND principal_kind='agent'",
            rusqlite::params![project, target],
            |r| r.get(0),
        )
        .optional()
        .map_err(sql)?;
    match created_by {
        None => Err(fail(
            StoreErrorCode::ReferenceMissing,
            "creator-control target agent is not registered in this project",
        )),
        Some(Some(by)) if by == creator_key => Ok(()),
        Some(_) => Err(fail(
            StoreErrorCode::CreatorControlRefused,
            "target is not this creator's direct helper; use owner control or its actual creator",
        )),
    }
}
