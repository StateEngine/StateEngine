//! Native custody tests use invalid dummy credentials, never a real provider token.
#![cfg(any(target_os = "linux", windows))]
#[path = "../../test-support/directory.rs"]
mod cleanup_directory;
use se_host::channels::{ChannelError, NativeChannelCredentials};
use se_types::{HumanId, StoreId};
use std::io::Write;
type Check = Result<(), Box<dyn std::error::Error>>;

/// Protects: a malformed credential carrier refuses with its real cause, so the
/// owner can tell which custody fact failed instead of a bare code.
#[test]
fn a_malformed_carrier_name_reports_its_cause() -> Check {
    let home = cleanup_directory::private_case_directory()?;
    drop(se_proc::NativeStateFiles::create(&home)?);
    let home = home.cleanup_on_drop();
    let store = StoreId::from_parts(1_700_000_000_000, [1; 10])?;
    let owner = HumanId::from_parts(1_700_000_000_001, [2; 10])?;
    let vault = NativeChannelCredentials::open(&home, store.clone(), owner.clone())?;
    let files = se_proc::NativeStateFiles::open(&home.join("channel-credentials"))?;
    let mut staged = files.create_staging(files.root())?;
    staged
        .file
        .write_all(b"123456:dummy_invalid_provider_token_123456")?;
    drop(staged.file);
    let name = format!("channel-{store}-{owner}-ccr-0123456789abcdef0123456789abcdef");
    files.publish_no_replace(&staged.path, &files.root().join(name))?;
    match vault.catalog() {
        Err(ChannelError::CredentialStoreUnavailable { cause }) => {
            assert!(
                cause.contains("revision"),
                "cause lost the failed fact: {cause}"
            );
            let text = ChannelError::CredentialStoreUnavailable {
                cause: cause.clone(),
            }
            .to_string();
            assert!(text.starts_with("credential_store_unavailable (") && text.contains(&cause));
            assert!(
                !text.contains("dummy_invalid"),
                "token bytes reached the cause"
            );
            Ok(())
        }
        other => Err(format!("expected a caused custody refusal, got {other:?}").into()),
    }
}
