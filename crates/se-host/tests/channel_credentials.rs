//! Native custody tests use invalid dummy credentials, never a real provider token.
#![cfg(any(target_os = "linux", windows))]
use se_host::channels::{ChannelError, NativeChannelCredentials};
use se_types::{HumanId, StoreId};
use std::path::PathBuf;
type Check = Result<(), Box<dyn std::error::Error>>;
struct Home(PathBuf);
impl Home {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let path = std::env::temp_dir().join(format!(
            "se-channel-custody-{}",
            se_types::hex_lower(se_proc::random_secret()?.expose())
        ));
        drop(se_proc::NativeStateFiles::create(&path)?);
        Ok(Self(path))
    }
    fn vault(&self) -> Result<NativeChannelCredentials, ChannelError> {
        NativeChannelCredentials::open(
            &self.0,
            StoreId::from_parts(1_700_000_000_000, [1; 10])
                .map_err(|_| ChannelError::InvalidInput)?,
            HumanId::from_parts(1_700_000_000_001, [2; 10])
                .map_err(|_| ChannelError::InvalidInput)?,
        )
    }
}
impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
const DUMMY: &[u8] = b"123456:dummy_invalid_provider_token_123456\n";
/// Protects: 49 — preserve immutable native token references across restart and delayed deletion.
#[test]
fn immutable_references_survive_reopen_and_old_forget_cannot_delete_replacement() -> Check {
    let home = Home::new()?;
    let vault = home.vault()?;
    let first = vault.provision(&mut &DUMMY[..])?;
    let second = vault.provision(&mut &DUMMY[..])?;
    assert_ne!(first.id, second.id);
    let catalog = vault.catalog()?;
    assert!(catalog.complete);
    assert_eq!(catalog.credentials.len(), 2);
    let encoded = serde_json::to_string(&catalog)?;
    assert!(!encoded.contains("dummy_invalid"));
    drop(vault);
    let vault = home.vault()?;
    assert_eq!(vault.resolve(&first)?.expose(), &DUMMY[..DUMMY.len() - 1]);
    vault.forget(&first)?;
    vault.forget(&first)?;
    assert!(matches!(
        vault.resolve(&first),
        Err(ChannelError::CredentialAbsent)
    ));
    assert_eq!(vault.resolve(&second)?.expose(), &DUMMY[..DUMMY.len() - 1]);
    assert_eq!(vault.catalog()?.credentials, vec![second]);
    Ok(())
}
/// Protects: 49 — refuse foreign or incomplete credential custody without claiming an empty store.
#[test]
fn foreign_scope_and_corrupt_carrier_refuse_without_empty_catalog_or_deletion() -> Check {
    let home = Home::new()?;
    let vault = home.vault()?;
    let reference = vault.provision(&mut &DUMMY[..])?;
    let mut forged = reference.clone();
    forged.revision = 0;
    assert!(matches!(
        vault.forget(&forged),
        Err(ChannelError::CredentialScopeMismatch)
    ));
    assert!(vault.resolve(&reference).is_ok());
    let files = se_proc::NativeStateFiles::open(&home.0.join("channel-credentials"))?;
    let orphan = files.create_staging(files.root())?;
    drop(orphan.file);
    assert!(matches!(
        vault.catalog(),
        Err(ChannelError::CredentialScopeMismatch) | Err(ChannelError::CredentialStoreUnavailable)
    ));
    Ok(())
}
/// Protects: 49 — reject malformed or over-budget protected token input before publication.
#[test]
fn malformed_and_oversized_tokens_never_create_credential_references() -> Check {
    let home = Home::new()?;
    let vault = home.vault()?;
    assert!(matches!(
        vault.provision(&mut &b"not a token"[..]),
        Err(ChannelError::InvalidToken)
    ));
    assert!(matches!(
        vault.provision(&mut &vec![b'9'; 258][..]),
        Err(ChannelError::InvalidToken)
    ));
    assert!(vault.catalog()?.credentials.is_empty());
    Ok(())
}
