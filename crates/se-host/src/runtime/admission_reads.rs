//! Native database custody for the store's bounded idle admission connections.
use se_store::{ReadConnectionIdentity, StoreError, StoreErrorCode, StoreResult};
use std::path::Path;
struct Identity(se_proc::NativeSourcePin);
impl ReadConnectionIdentity for Identity {
    fn validate(&self, path: &Path) -> StoreResult<()> {
        self.0
            .validate_path(path)
            .map_err(crate::state_files::native_error)
    }
}
pub(crate) fn pin(path: &Path) -> StoreResult<Box<dyn ReadConnectionIdentity>> {
    let pin = se_proc::NativeSourcePin::open(path)
        .map_err(crate::state_files::native_error)?
        .ok_or_else(|| Box::new(StoreError {
            code: StoreErrorCode::Absent,
            cause: format!("native database file is absent at {}", path.display()),
            detail: se_store::StoreDetail::None,
            remedy: se_types::Remedy {
                text: "Preserve the state directory and diagnose the absent database before restarting the host.".into(),
                command: None,
            },
            retry: se_types::Retry::Never,
        }))?;
    Ok(Box::new(Identity(pin)))
}
