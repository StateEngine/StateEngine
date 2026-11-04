//! Resume exposes one stable refusal for malformed, foreign and stale positions.
use se_types::{Cursor, Detail, Result, SeError, details};

pub(crate) fn invalid_cursor(reason: impl Into<String>) -> SeError {
    SeError::new(Detail::CursorInvalid(details::CursorInvalid {
        reason: reason.into(),
        next_step: "Retry without --since (CLI), or omit since from the MCP request, to request a fresh context window.".into(),
    }))
}
pub(crate) fn resume_since(value: String) -> Result<Cursor> {
    Cursor::new(value).map_err(|_| invalid_cursor("malformed resume cursor"))
}
pub(crate) fn validate_resume_since(arguments: &serde_json::Value) -> Result<()> {
    if let Some(value) = arguments.get("since").filter(|value| !value.is_null()) {
        let value = value
            .as_str()
            .ok_or_else(|| invalid_cursor("resume since must be a cursor string"))?;
        resume_since(value.into())?;
    }
    Ok(())
}
pub(super) fn store_cursor_error(error: &se_store::StoreError) -> SeError {
    let error = crate::store_error::store_error(error);
    match error.body.detail() {
        Detail::CursorInvalid(detail) => invalid_cursor(detail.reason.clone()),
        _ => error,
    }
}
