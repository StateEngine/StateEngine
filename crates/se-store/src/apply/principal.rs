//! Name uniqueness is checked inside the writer transaction, including races.
use crate::{error::*, identity, *};
use rusqlite::{Connection, OptionalExtension};
pub(super) fn name_available(
    c: &Connection,
    scope: &Scope,
    principal: &Actor,
    name: &str,
) -> StoreResult<()> {
    let Scope::Project(project) = scope else {
        return Ok(());
    };
    let key = identity::scope_key(c, scope, false)?;
    let existing: Option<Vec<u8>> = c
        .query_row(
            "SELECT principal_id FROM principals WHERE project_id=? AND display_name=?",
            crate::sql_value::sql_params![crate::connection::project_id(c, scope, false)?, name],
            |row| crate::sql_value::value(row, 0),
        )
        .optional()
        .map_err(sql)?;
    if let Some(existing) = existing {
        let existing = identity::actor(c, &existing, &key)?;
        if existing != *principal {
            let mut error = fail(
                StoreErrorCode::AlreadyExists,
                "a principal already has this name in the selected project",
            );
            error.detail = StoreDetail::PrincipalNameConflict {
                project: project.clone(),
                name: name.into(),
                existing,
            };
            error.remedy.text = "Choose another name, or use the existing principal.".into();
            return Err(error);
        }
    }
    Ok(())
}
