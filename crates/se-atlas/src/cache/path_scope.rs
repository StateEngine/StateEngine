//! Bounded, allocation-free file/directory selection before SQL candidate limits.
use crate::errors::{AtlasResult, cache_error};
use rusqlite::{Connection, functions::FunctionFlags, types::ValueRef};
pub(crate) fn register(db: &Connection) -> AtlasResult<()> {
    db.create_scalar_function(
        "atlas_scope",
        4,
        FunctionFlags::SQLITE_UTF8
            | FunctionFlags::SQLITE_DETERMINISTIC
            | FunctionFlags::SQLITE_INNOCUOUS,
        |context| {
            let path = context.get_raw(0).as_str()?.as_bytes();
            let language = match context.get_raw(1) {
                ValueRef::Null => None,
                value => Some(value.as_str()?.as_bytes()),
            };
            let paths = context.get_raw(2).as_blob()?;
            let languages = context.get_raw(3).as_blob()?;
            if paths.len() > 8192 || languages.len() > 512 {
                return Err(rusqlite::Error::UserFunctionError(
                    "Atlas scope exceeds its path/language byte budget".into(),
                ));
            }
            let selected = paths.is_empty()
                || paths
                    .split(|b| *b == 0)
                    .filter(|p| !p.is_empty())
                    .any(|prefix| {
                        path == prefix
                            || path
                                .strip_prefix(prefix)
                                .is_some_and(|tail| tail.starts_with(b"/"))
                    });
            let selected_language = languages.is_empty()
                || language.is_some_and(|language| {
                    languages.split(|b| *b == 0).any(|entry| entry == language)
                });
            Ok(selected && selected_language)
        },
    )
    .map_err(cache_error)
}
