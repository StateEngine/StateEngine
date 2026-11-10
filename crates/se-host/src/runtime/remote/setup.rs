//! Explicit remote calls load existing protected identity; they never mint keys.
use super::*;
use crate::remote::{
    CredentialSource, RemoteHostId, bindings::ProtectedBindings, client::ClientConnector,
    keys::ProtectedCredential,
};
pub(super) async fn ensure(
    context: &ExecutionContext,
    deadline: &crate::client::lease::Deadline,
) -> Result<()> {
    if context.mail_waits.remote().is_some() {
        return Ok(());
    }
    let root = context.state_directory.clone();
    let (host, records) = context
        .blocking
        .run_owned(deadline, move || {
            let files: Arc<dyn se_store::StateFiles> = Arc::new(
                crate::state_files::Files::open_with_policy(
                    &root,
                    crate::state_files::FilePolicy::Host,
                )
                .map_err(|error| se_core::store_error::store_error(&error))?,
            );
            // A source-only host has a persistent identity after native Owner pairing.
            // Missing or unreadable keys refuse; an agent call cannot repair them.
            let key = ProtectedCredential::open(
                files.clone(),
                root.join("remote-keys/host.identity.key"),
            )?;
            let host = RemoteHostId(se_types::Sha256::from_bytes(key.credential_sha256()));
            Ok((host, Arc::new(ProtectedBindings::new(files, root))))
        })
        .await?;
    let connector = Arc::new(ClientConnector::with_forwards(
        context.blocking.clone(),
        context.mail_waits.forwards(),
    ));
    let broker = Arc::new(RemoteBroker::from_protected(
        host,
        connector,
        records,
        context.blocking.clone(),
    ));
    match context.mail_waits.install_remote(broker) {
        Ok(()) => Ok(()),
        // Concurrent first calls may install the same protected identity. Never
        // accept an unrelated explicit broker or an identity rotated mid-load.
        Err(error) => match context.mail_waits.remote() {
            Some(current) if current.source_host() == host => Ok(()),
            _ => Err(error),
        },
    }
}
