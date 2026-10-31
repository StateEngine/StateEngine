//! Context at the store I/O boundary. Never inspect ambient last-error state.
use super::*;
use std::path::Path;

pub(crate) fn context(
    mut error: Box<StoreError>,
    path: &Path,
    stage: StoreIoStage,
) -> Box<StoreError> {
    if matches!(error.detail, StoreDetail::Io { .. }) {
        return error;
    }
    let (sqlite_extended_code, native_os_code) = match error.detail {
        StoreDetail::Sqlite {
            extended_code,
            native_os_code,
        } => (Some(extended_code), native_os_code),
        _ => (None, None),
    };
    attach(
        &mut error,
        path,
        stage,
        sqlite_extended_code,
        native_os_code,
    );
    error
}
pub(crate) fn sqlite_context(
    error: rusqlite::Error,
    path: &Path,
    stage: StoreIoStage,
) -> Box<StoreError> {
    context(sql(error), path, stage)
}
pub(crate) fn io(error: std::io::Error, path: &Path, stage: StoreIoStage) -> Box<StoreError> {
    let native_os_code = error.raw_os_error();
    let mut error = fail(StoreErrorCode::Unreadable, error.to_string());
    attach(&mut error, path, stage, None, native_os_code);
    error
}
fn attach(
    error: &mut StoreError,
    path: &Path,
    stage: StoreIoStage,
    sqlite_extended_code: Option<i32>,
    native_os_code: Option<i32>,
) {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "state.db".into());
    let relative = if name == "state.db" {
        name
    } else {
        match path
            .parent()
            .and_then(Path::file_name)
            .and_then(|part| part.to_str())
        {
            Some("backups") => format!("backups/{name}"),
            Some("staging") => format!("staging/{name}"),
            _ => name,
        }
    };
    let opened_path = path.to_string_lossy().into_owned();
    let sqlite = sqlite_extended_code
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unavailable".into());
    let native = native_os_code
        .map(|value| format!("{value} ({})", std::io::Error::from_raw_os_error(value)))
        .unwrap_or_else(|| "unavailable".into());
    let facts = format!(
        "path={relative:?}, opened_path={opened_path:?}, stage={stage:?}, sqlite_extended_code={sqlite}, native_os_code={native}"
    );
    error.cause = format!("{}; {facts}", error.cause);
    error.remedy.text = format!("{facts}. {}", error.remedy.text);
    error.detail = StoreDetail::Io {
        path: relative,
        opened_path,
        stage,
        sqlite_extended_code,
        native_os_code,
    };
}
