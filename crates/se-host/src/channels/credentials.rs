//! Channel-scoped custody through the same native protected file owner used by
//! the machine credential. Token bytes never enter SQLite, request DTOs or argv.
use super::{ChannelError as Error, ChannelResult, CredentialId, CredentialRef};
use se_types::{HumanId, Secret, StoreId};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

/// Constructed only by the trusted native Owner entry for an already protected
/// home. It is not deserializable, an agent tool, or an ordinary HTTP capability.
pub struct NativeChannelCredentials {
    files: se_proc::NativeStateFiles,
    store: StoreId,
    owner: HumanId,
}
impl NativeChannelCredentials {
    pub fn open(home: &std::path::Path, store: StoreId, owner: HumanId) -> ChannelResult<Self> {
        let home_files =
            se_proc::NativeStateFiles::open(home).map_err(|_| Error::CredentialStoreUnavailable)?;
        let root = home.join("channel-credentials");
        home_files
            .prepare_directory(&root)
            .map_err(|_| Error::CredentialStoreUnavailable)?;
        let files = se_proc::NativeStateFiles::open(&root)
            .map_err(|_| Error::CredentialStoreUnavailable)?;
        Ok(Self {
            files,
            store,
            owner,
        })
    }
    /// Protected masked native-field sink. Every provision allocates a new
    /// immutable ID, so a delayed forget cannot touch a later provision.
    pub fn provision(&self, input: &mut dyn Read) -> ChannelResult<CredentialRef> {
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        input
            .take(257)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::CredentialStoreUnavailable)?;
        if bytes.last() == Some(&b'\n') {
            bytes.pop();
            if bytes.last() == Some(&b'\r') {
                bytes.pop();
            }
        }
        validate_token(&bytes)?;
        let random = se_proc::random_secret().map_err(|_| Error::CredentialStoreUnavailable)?;
        let id = CredentialId::new(format!(
            "ccr-{}",
            se_types::hex_lower(&random.expose()[..16])
        ))
        .map_err(|_| Error::InvalidInput)?;
        let reference = CredentialRef {
            store: self.store.clone(),
            owner: self.owner.clone(),
            id,
            revision: 1,
        };
        let path = self.path(&reference)?;
        let mut stage = self
            .files
            .create_staging(self.files.root())
            .map_err(|_| Error::CredentialStoreUnavailable)?;
        stage
            .file
            .write_all(&bytes)
            .and_then(|()| stage.file.sync_all())
            .map_err(|_| Error::CredentialStoreUnavailable)?;
        drop(stage.file);
        self.files
            .publish_no_replace(&stage.path, &path)
            .map_err(|_| Error::CredentialStoreUnavailable)?;
        let actual = self.resolve(&reference)?;
        if actual.expose() != bytes.as_slice() {
            return Err(Error::CredentialStoreUnavailable);
        }
        Ok(reference)
    }
    fn path(&self, reference: &CredentialRef) -> ChannelResult<std::path::PathBuf> {
        if reference.store != self.store
            || reference.owner != self.owner
            || reference.revision == 0
            || reference.revision > i64::MAX as u64
        {
            return Err(Error::CredentialScopeMismatch);
        }
        Ok(self.files.root().join(format!(
            "channel-{}-{}-{}-r{}",
            self.store, self.owner, reference.id, reference.revision
        )))
    }
    fn read(&self, path: &std::path::Path) -> ChannelResult<Secret> {
        let file = self
            .files
            .readback(path)
            .map_err(|_| Error::CredentialStoreUnavailable)?
            .ok_or(Error::CredentialAbsent)?;
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        file.take(257)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::CredentialStoreUnavailable)?;
        validate_token(&bytes)?;
        Secret::new(std::mem::take(&mut *bytes)).map_err(|_| Error::InvalidToken)
    }
}
impl NativeChannelCredentials {
    pub fn catalog(&self) -> ChannelResult<super::CredentialCatalog> {
        let names = self
            .files
            .list_owned(self.files.root())
            .map_err(|_| Error::CredentialStoreUnavailable)?;
        let prefix = format!("channel-{}-{}-", self.store, self.owner);
        let mut credentials = Vec::new();
        for path in names {
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or(Error::CredentialStoreUnavailable)?;
            let suffix = name
                .strip_prefix(&prefix)
                .ok_or(Error::CredentialScopeMismatch)?;
            let (id, revision) = suffix
                .rsplit_once("-r")
                .ok_or(Error::CredentialStoreUnavailable)?;
            let reference = CredentialRef {
                store: self.store.clone(),
                owner: self.owner.clone(),
                id: CredentialId::new(id).map_err(|_| Error::CredentialStoreUnavailable)?,
                revision: revision
                    .parse()
                    .map_err(|_| Error::CredentialStoreUnavailable)?,
            };
            // Every listed reference must resolve through the same custody checks;
            // a corrupt or replaced carrier makes the catalog unreadable, not empty.
            self.resolve(&reference)?;
            credentials.push(reference);
        }
        credentials.sort_by(|a, b| a.id.as_str().cmp(b.id.as_str()));
        let omitted = credentials.len().saturating_sub(100) as u64;
        credentials.truncate(100);
        Ok(super::CredentialCatalog {
            credentials,
            complete: omitted == 0,
            omitted,
        })
    }
    pub fn resolve(&self, reference: &CredentialRef) -> ChannelResult<Secret> {
        let path = self.path(reference)?;
        let secret = self.read(&path)?;
        if self.read(&path)?.expose() != secret.expose() {
            return Err(Error::CredentialStoreUnavailable);
        }
        Ok(secret)
    }
    pub fn forget(&self, reference: &CredentialRef) -> ChannelResult<()> {
        let path = self.path(reference)?;
        let secret = match self.read(&path) {
            Ok(v) => v,
            Err(Error::CredentialAbsent) => return Ok(()),
            Err(e) => return Err(e),
        };
        let file = se_proc::OwnedFile::open(&path)
            .map_err(|_| Error::CredentialStoreUnavailable)?
            .ok_or(Error::CredentialAbsent)?;
        file.remove(Sha256::digest(secret.expose()).into())
            .map_err(|_| Error::CredentialStoreUnavailable)?;
        if self
            .files
            .readback(&path)
            .map_err(|_| Error::CredentialStoreUnavailable)?
            .is_some()
        {
            return Err(Error::CredentialStoreUnavailable);
        }
        Ok(())
    }
}
pub(super) fn validate_token(bytes: &[u8]) -> ChannelResult<()> {
    let Some(colon) = bytes.iter().position(|b| *b == b':') else {
        return Err(Error::InvalidToken);
    };
    if !(1..=20).contains(&colon)
        || !bytes[..colon].iter().all(u8::is_ascii_digit)
        || !(20..=128).contains(&(bytes.len() - colon - 1))
        || !bytes[colon + 1..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(b))
    {
        return Err(Error::InvalidToken);
    }
    Ok(())
}
