use se_core::store_error::store_error;
use se_store::{StoreDetail, StoreError, StoreErrorCode};
use se_types::{ErrorEnvelope, Remedy, RenderCx, Retry};
type Check = Result<(), Box<dyn std::error::Error>>;

/// Protects: unsafe custody is reported with its actual native cause and legal
/// recovery, rather than inventing a disk-type diagnosis from a broad store code.
#[test]
fn unsafe_custody_keeps_its_cause_and_recovery_in_public_output() -> Check {
    for cause in [
        r"protected directory DACL required at C:\Users\owner\state: LocationUnsafe",
        "owned state effect is outside its retained root",
    ] {
        let recovery = "Preserve the existing state and use a new private --home directory.";
        let source = StoreError {
            code: StoreErrorCode::LocationUnsafe,
            cause: cause.into(),
            detail: StoreDetail::None,
            remedy: Remedy {
                text: recovery.into(),
                command: None,
            },
            retry: Retry::Never,
        };
        let mapped = store_error(&source);
        let public = ErrorEnvelope::new(mapped.body.clone(), &RenderCx::default())?;
        let value = serde_json::to_value(public)?;
        assert!(
            value["message"]
                .as_str()
                .is_some_and(|text| text.contains(cause))
        );
        assert_eq!(value["remedy"]["text"], recovery);
        assert!(
            !value["message"]
                .as_str()
                .is_some_and(|text| text.contains("local disk"))
        );
        assert!(
            std::error::Error::source(&mapped)
                .is_some_and(|retained| retained.to_string().contains(cause))
        );
    }
    Ok(())
}
