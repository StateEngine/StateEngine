//! Protected machine credentials; SSH supplies the transport authentication.
use se_core::scope;
use se_store::StateFiles;
use se_types::{Result, Secret};
use sha2::{Digest, Sha256};
use std::{
    io::Read as _,
    path::{Path, PathBuf},
    sync::Arc,
};
mod cursors;
mod initialize;
use super::{CredentialSource, LinkSecret};
pub use cursors::CursorCipher;
pub struct ProtectedCredential {
    files: Arc<dyn StateFiles>,
    path: PathBuf,
    digest: [u8; 32],
}
impl ProtectedCredential {
    pub fn open(files: Arc<dyn StateFiles>, path: PathBuf) -> Result<Self> {
        let secret = read(&*files, &path)?;
        Ok(Self {
            files,
            path,
            digest: Sha256::digest(secret.expose()).into(),
        })
    }
    pub fn initialize(
        owner: &super::auth::VerifiedLocalOwner,
        files: Arc<dyn StateFiles>,
        path: PathBuf,
    ) -> Result<Self> {
        initialize::file(owner, &*files, &path)?;
        Self::open(files, path)
    }
}
impl CredentialSource for ProtectedCredential {
    fn credential_sha256(&self) -> [u8; 32] {
        self.digest
    }
    fn credential(&self) -> Result<LinkSecret> {
        let secret = read(&*self.files, &self.path)?;
        let digest: [u8; 32] = Sha256::digest(secret.expose()).into();
        if digest != self.digest {
            return Err(scope::unreadable(
                "machine session",
                "credential changed; re-admit the saved machine",
            ));
        }
        Ok(LinkSecret::new(secret.expose().try_into().map_err(
            |_| scope::unreadable("machine session", "32 protected bytes"),
        )?))
    }
}
fn read(files: &dyn StateFiles, path: &Path) -> Result<Secret> {
    let read = files
        .readback(path)
        .map_err(|e| se_core::store_error::store_error(&e))?;
    let file = scope::require_present(
        read,
        "machine credential",
        "Restore the original protected credential or explicitly reconnect through SSH; ordinary use never creates credentials.",
    )?;
    let mut bytes = Vec::new();
    let result = file.take(33).read_to_end(&mut bytes);
    let secret = Secret::new(bytes);
    if let Err(error) = result {
        drop(secret);
        return Err(scope::unreadable("machine credential", &error.to_string()));
    }
    let secret = secret
        .map_err(|_| scope::unreadable("machine credential", "key bytes absent or malformed"))?;
    if secret.expose().len() != 32 {
        return Err(scope::unreadable(
            "machine credential",
            "expected exactly 32 protected bytes",
        ));
    }
    Ok(secret)
}
