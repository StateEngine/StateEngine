//! Purpose-separated persistent AEAD key. Native protection is checked on every use.
use super::{initialize, read};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use se_core::scope;
use se_store::StateFiles;
use se_types::Result;
use sha2::{Digest, Sha256};
use std::{path::PathBuf, sync::Arc};
const PAYLOAD: usize = 2048;
const HEADER: usize = 1 + 16 + 24;
const DOMAIN: &[u8] = b"stateengine.remote.cursor/v1\0";
/// Holds native custody and a public key identifier, never cached private key bytes.
/// Call load/initialize/seal/open on the existing bounded blocking pool.
pub struct CursorCipher {
    files: Arc<dyn StateFiles>,
    path: PathBuf,
    key_id: [u8; 16],
}
impl CursorCipher {
    pub fn initialize(
        owner: &super::super::auth::VerifiedLocalOwner,
        files: Arc<dyn StateFiles>,
        state_directory: PathBuf,
    ) -> Result<Self> {
        initialize::file(
            owner,
            &*files,
            &state_directory.join("remote-keys/cursors.aead"),
        )?;
        Self::load(files, state_directory)
    }
    pub fn load(files: Arc<dyn StateFiles>, state_directory: PathBuf) -> Result<Self> {
        let path = state_directory.join("remote-keys/cursors.aead");
        let secret = read(&*files, &path)?;
        let digest = Sha256::digest(secret.expose());
        let mut key_id = [0; 16];
        key_id.copy_from_slice(&digest[..16]);
        Ok(Self {
            files,
            path,
            key_id,
        })
    }
    fn cipher(&self) -> Result<XChaCha20Poly1305> {
        let secret = read(&*self.files, &self.path)?;
        if Sha256::digest(secret.expose())[..16] != self.key_id {
            return Err(reset());
        }
        XChaCha20Poly1305::new_from_slice(secret.expose()).map_err(|_| reset())
    }
    /// Binary envelope; the shared codec supplies its one canonical cursor spelling.
    /// Associated data must bind the reader's host/store/grant/revision/filter/schema.
    pub fn seal(&self, plaintext: &[u8], associated: &[u8]) -> Result<Vec<u8>> {
        let aad = associated_data(associated)?;
        if plaintext.is_empty() || plaintext.len() > PAYLOAD {
            return Err(scope::unreadable(
                "remote cursor",
                "cursor payload must be 1..2048 bytes",
            ));
        }
        let cipher = self.cipher()?;
        let nonce = super::super::session::entropy::<24>()?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| reset())?;
        let mut out = Vec::with_capacity(HEADER + ciphertext.len());
        out.push(1);
        out.extend_from_slice(&self.key_id);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }
    pub fn open(&self, envelope: &[u8], associated: &[u8]) -> Result<Vec<u8>> {
        let aad = associated_data(associated)?;
        if !(HEADER + 17..=HEADER + 16 + PAYLOAD).contains(&envelope.len())
            || envelope[0] != 1
            || envelope[1..17] != self.key_id
        {
            return Err(reset());
        }
        self.cipher()?
            .decrypt(
                XNonce::from_slice(&envelope[17..HEADER]),
                Payload {
                    msg: &envelope[HEADER..],
                    aad: &aad,
                },
            )
            .map_err(|_| reset())
    }
}
fn associated_data(associated: &[u8]) -> Result<Vec<u8>> {
    if associated.is_empty() || associated.len() > 4096 {
        return Err(scope::unreadable(
            "remote cursor",
            "explicit scoped associated data must be 1..4096 bytes",
        ));
    }
    let mut out = DOMAIN.to_vec();
    out.extend_from_slice(&(associated.len() as u32).to_be_bytes());
    out.extend_from_slice(associated);
    Ok(out)
}
fn reset() -> se_types::SeError {
    scope::unreadable(
        "remote cursor",
        "cursor authentication or protected key binding failed; explicitly reset this scoped watch, preserve key-loss diagnostics, and never accept an unsigned cursor",
    )
}
