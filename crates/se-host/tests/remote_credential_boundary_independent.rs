//! An owner-run fixture exercises retained native admission after key rotation.
#![cfg(all(feature = "remote", target_os = "linux"))]
use se_host::{
    client::{
        BlockingIpcClient, ClientOptions, endpoint::decode_endpoint, lease::ClientCredential,
    },
    *,
};
use se_types::Secret;
use std::{
    error::Error,
    fs,
    num::NonZeroU32,
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};
type Check<T = ()> = Result<T, Box<dyn Error>>;
struct RestoreKey {
    path: PathBuf,
    original: Vec<u8>,
}
impl Drop for RestoreKey {
    fn drop(&mut self) {
        // The enclosing owner-run probe independently restores and joins its host.
        let _ = fs::write(&self.path, &self.original);
    }
}
fn identity(endpoint: &EndpointRecord) -> IpcEnvelope {
    IpcEnvelope {
        version: se_types::API_VERSION,
        request_id: 1,
        generation: endpoint.generation,
        authority: None,
        presence: None,
        cli_selections: None,
        request: IpcRequest::RemoteOwner(Box::new(remote::OwnerInput::MachineIdentity)),
    }
}
/// Invoked only by a reviewer-owned owner-context script with a fresh native home.
#[test]
#[ignore = "requires an explicitly supplied isolated owner-run host fixture"]
fn retained_native_connection_rejects_the_replaced_machine_credential() -> Check {
    let root = PathBuf::from(
        std::env::var_os("SE_NATIVE_CREDENTIAL_FIXTURE").ok_or("missing private fixture")?,
    );
    assert_eq!(
        fs::read(root.join("independent-fixture"))?,
        b"synthetic native credential fixture\n"
    );
    let endpoint = decode_endpoint(&fs::read(root.join("endpoint.json"))?)?;
    let key = RestoreKey {
        path: root.join("credential"),
        original: fs::read(root.join("credential"))?,
    };
    assert_eq!(key.original.len(), 32);
    let options = ClientOptions {
        expected_generation: Some(endpoint.generation),
        timeout: Duration::from_secs(20),
        cancelled: Arc::new(AtomicBool::new(false)),
    };
    let connect = |bytes: &[u8]| {
        BlockingIpcClient::connect_authenticated(
            &endpoint,
            ClientCredential::Machine(Secret::new(bytes.to_vec())?),
            NonZeroU32::new(65536)
                .ok_or_else(|| se_types::SeError::invalid("fixture", "nonzero reply budget"))?,
            &options,
        )
    };
    let mut retained = connect(&key.original)?;
    let before = retained.exchange(identity(&endpoint), &options)?;
    let mut replacement = key.original.clone();
    replacement[0] ^= 1;
    fs::write(&key.path, &replacement)?;
    let refusal = retained
        .exchange(identity(&endpoint), &options)
        .err()
        .ok_or("retained old-key authority admitted")?;
    assert!(
        refusal.to_string().contains("credential"),
        "unexpected retained refusal: {refusal}"
    );
    let refusal = connect(&key.original)
        .err()
        .ok_or("new connection authenticated with stale key")?;
    assert!(
        refusal.to_string().contains("proof") || refusal.to_string().contains("credential"),
        "unexpected stale-key refusal: {refusal}"
    );
    let mut current = connect(&replacement)?;
    let after = current.exchange(identity(&endpoint), &options)?;
    assert_eq!(before.value, after.value);
    assert_eq!(
        fs::read(&key.path)?,
        replacement,
        "ordinary requests replaced current credential"
    );
    drop(current);
    drop(retained);
    fs::write(&key.path, &key.original)?;
    let mut restored = connect(&key.original)?;
    assert_eq!(
        restored.exchange(identity(&endpoint), &options)?.value,
        before.value
    );
    Ok(())
}
