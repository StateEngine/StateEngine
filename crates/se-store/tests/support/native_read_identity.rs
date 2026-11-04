//! Real native identity custody supplied through the public store port.
use se_store::{ReadConnectionIdentity, StoreDetail, StoreError, StoreErrorCode, StoreResult};
use std::path::Path;

struct NativeIdentity(se_proc::NativeSourcePin);
fn refused(code: StoreErrorCode, reason: impl ToString) -> Box<StoreError> {
    Box::new(StoreError {
        code,
        cause: reason.to_string(),
        detail: StoreDetail::None,
        remedy: se_types::Remedy {
            text: "Restore the original native database identity.".into(),
            command: None,
        },
        retry: se_types::Retry::AfterReread,
    })
}
fn native_error(error: se_proc::StateFileError) -> Box<StoreError> {
    let code = match error.code {
        se_proc::StateFileErrorCode::SourceChanged => StoreErrorCode::SourceChanged,
        se_proc::StateFileErrorCode::LocationUnsafe => StoreErrorCode::LocationUnsafe,
        _ => StoreErrorCode::Unreadable,
    };
    refused(code, error)
}
impl ReadConnectionIdentity for NativeIdentity {
    fn validate(&self, path: &Path) -> StoreResult<()> {
        self.0.validate_path(path).map_err(native_error)
    }
}
pub fn open_identity(path: &Path) -> StoreResult<Box<dyn ReadConnectionIdentity>> {
    let pin = se_proc::NativeSourcePin::open(path)
        .map_err(native_error)?
        .ok_or_else(|| refused(StoreErrorCode::Absent, "database absent"))?;
    Ok(Box::new(NativeIdentity(pin)))
}
