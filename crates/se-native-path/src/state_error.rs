//! Native state-path error facts and their original formatting.
use std::{
    io,
    path::{Path, PathBuf},
};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateFileErrorCode {
    AlreadyExists,
    Unreadable,
    LocationUnsafe,
    SourceChanged,
    Unsupported,
}
#[derive(Debug)]
pub struct StateFileError {
    pub code: StateFileErrorCode,
    pub operation: &'static str,
    pub path: PathBuf,
    pub source: Option<io::Error>,
}
impl StateFileError {
    /// A measured nonblocking native lock refusal, distinct from access failure.
    pub fn is_contended(&self) -> bool {
        self.source.as_ref().is_some_and(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                return true;
            }
            #[cfg(windows)]
            if matches!(error.raw_os_error(), Some(32 | 33)) {
                return true;
            } // ERROR_SHARING_VIOLATION / ERROR_LOCK_VIOLATION
            false
        })
    }
}
impl std::fmt::Display for StateFileError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "{} at {}: {:?}",
            self.operation,
            self.path.display(),
            self.code
        )?;
        if let Some(source) = &self.source {
            write!(out, ": {source}")?;
        }
        Ok(())
    }
}
impl std::error::Error for StateFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| e as _)
    }
}
pub type Result<T> = std::result::Result<T, StateFileError>;
pub fn failure(code: StateFileErrorCode, operation: &'static str, path: &Path) -> StateFileError {
    StateFileError {
        code,
        operation,
        path: path.to_owned(),
        source: None,
    }
}
pub fn io_error(operation: &'static str, path: &Path, source: io::Error) -> StateFileError {
    #[cfg(unix)]
    if source.raw_os_error() == Some(libc::ELOOP) {
        return StateFileError {
            code: StateFileErrorCode::LocationUnsafe,
            operation,
            path: path.to_owned(),
            source: Some(source),
        };
    }
    StateFileError {
        code: if source.kind() == io::ErrorKind::AlreadyExists {
            StateFileErrorCode::AlreadyExists
        } else {
            StateFileErrorCode::Unreadable
        },
        operation,
        path: path.to_owned(),
        source: Some(source),
    }
}
pub fn unsafe_path(operation: &'static str, path: &Path) -> StateFileError {
    failure(StateFileErrorCode::LocationUnsafe, operation, path)
}
/// A refusal that names the observed facts behind the check, so the reader
/// sees what was actually seen, not only that it failed.
#[cfg(unix)]
pub fn unsafe_path_observed(
    operation: &'static str,
    path: &Path,
    observed: String,
) -> StateFileError {
    StateFileError {
        code: StateFileErrorCode::LocationUnsafe,
        operation,
        path: path.to_owned(),
        source: Some(io::Error::other(observed)),
    }
}
