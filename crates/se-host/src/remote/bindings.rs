//! Native-owned alias records and sealed key lookup. No private key is serialized.
use super::{auth::VerifiedLocalOwner, keys::ProtectedCredential, *};
use se_core::scope;
use se_store::StateFiles;
use se_types::{Read, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::Read as _, net::SocketAddr, path::PathBuf, sync::Arc};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedBinding {
    #[cfg(feature = "remote")]
    #[serde(default)]
    pub forward: Option<ssh::ForwardConfig>,
    pub connected: bool,
    pub alias: String,
    pub route: SocketAddr,
    pub paired: MachineSession,
    pub credential_sha256: CredentialDigest,
}
impl SavedBinding {
    /// Lease renewal is fresh server state, not a change of local authority.
    pub(crate) fn same_authority(&self, other: &Self) -> bool {
        let mut expected = self.clone();
        expected.paired.expires_at = other.paired.expires_at;
        expected == *other
    }
}
pub struct BindingRecord {
    pub binding: SavedBinding,
    pub sha256: [u8; 32],
}
#[derive(Clone)]
pub struct ProtectedBindings {
    files: Arc<dyn StateFiles>,
    root: PathBuf,
}
impl ProtectedBindings {
    pub fn new(files: Arc<dyn StateFiles>, root: PathBuf) -> Self {
        Self { files, root }
    }
    pub fn key_path(&self, grant: &RemoteGrantId) -> PathBuf {
        self.root
            .join("remote-keys")
            .join(format!("{grant}.credential"))
    }
    fn path(&self, alias: &str) -> Result<PathBuf> {
        alias_name(alias)?;
        Ok(self
            .root
            .join("remote-bindings")
            .join(format!("{alias}.json")))
    }
    /// A finite protected read; absent, malformed and inaccessible stay distinct.
    pub fn read(&self, alias: &str) -> Result<Read<BindingRecord>> {
        let file = match self
            .files
            .readback(&self.path(alias)?)
            .map_err(|e| se_core::store_error::store_error(&e))?
        {
            Read::Present { value } => value,
            Read::Absent { checked } => return Ok(Read::Absent { checked }),
            Read::Unknown { what } => return Ok(Read::Unknown { what }),
            Read::Unreadable {
                source,
                reason,
                error,
            } => {
                return Ok(Read::Unreadable {
                    source,
                    reason,
                    error,
                });
            }
        };
        let mut bytes = Vec::new();
        file.take(65537)
            .read_to_end(&mut bytes)
            .map_err(|_| scope::unreadable("remote binding", "protected binding read failed"))?;
        if bytes.len() > 65536 {
            return Err(scope::unreadable(
                "remote binding",
                "binding exceeds 64 KiB",
            ));
        }
        let binding: SavedBinding = serde_json::from_slice(&bytes).map_err(|_| {
            scope::unreadable(
                "remote binding",
                "binding is malformed; preserve it and restore its protected record before reconnecting",
            )
        })?;
        if binding.alias != alias {
            return Err(scope::unreadable(
                "remote binding",
                "alias identity differs",
            ));
        }
        validate(&binding)?;
        Ok(Read::Present {
            value: BindingRecord {
                binding,
                sha256: Sha256::digest(bytes).into(),
            },
        })
    }
    /// Owner-controlled compare-and-publish through existing native custody.
    pub fn save(
        &self,
        owner: &VerifiedLocalOwner,
        binding: SavedBinding,
        expected: Option<[u8; 32]>,
    ) -> Result<BindingRecord> {
        if owner.deadline <= std::time::Instant::now() {
            return Err(scope::unreadable(
                "remote binding",
                "native Owner admission expired",
            ));
        }
        validate(&binding)?;
        let signer =
            ProtectedCredential::open(self.files.clone(), self.key_path(&binding.paired.grant))?;
        if signer.credential_sha256() != binding.credential_sha256.0 {
            return Err(scope::unreadable(
                "remote binding",
                "saved machine credential differs; preserve the original record before reconnecting",
            ));
        }
        self.files
            .prepare_directory(&self.root.join("remote-bindings"))
            .map_err(|e| se_core::store_error::store_error(&e))?;
        self.claim_machine(&binding)?;
        let bytes = serde_json::to_vec(&binding)
            .map_err(|_| scope::unreadable("remote binding", "binding encoding failed"))?;
        if bytes.len() > 65536 {
            return Err(scope::unreadable(
                "remote binding",
                "binding exceeds 64 KiB",
            ));
        }
        self.files
            .replace_owned(&self.path(&binding.alias)?, expected, &bytes)
            .map_err(|e| se_core::store_error::store_error(&e))?;
        scope::require_present(
            self.read(&binding.alias)?,
            "remote binding publication",
            "Read back the exact protected alias before connecting.",
        )
    }
    /// Called by the admitted native human consumer or source-session broker.
    /// The immutable context selects the grant subject before any key is loaded.
    pub fn lead_signer(
        &self,
        record: &BindingRecord,
        call: &RemoteCallContext,
    ) -> Result<Arc<dyn CredentialSource>> {
        if !matches!(record.binding.paired.subject, RemoteSubject::Machine { .. }) {
            return Err(scope::unreadable(
                "remote binding",
                "source broker requires an authenticated machine session",
            ));
        }
        call.check_current()?;
        call.invocation(
            &record.binding.paired,
            RemoteRequest::List(RemoteList {
                targets: vec![],
                cursor: None,
                limit: 1,
                budget: 1024,
            }),
        )?;
        self.signer(record)
    }
    pub fn human_signer(
        &self,
        owner: &VerifiedLocalOwner,
        record: &BindingRecord,
    ) -> Result<Arc<dyn CredentialSource>> {
        if owner.deadline <= std::time::Instant::now()
            || !matches!(record.binding.paired.subject, RemoteSubject::Machine { .. })
        {
            return Err(scope::unreadable(
                "remote binding",
                "current native owner admission and a machine session are required",
            ));
        }
        self.signer(record)
    }
    fn signer(&self, record: &BindingRecord) -> Result<Arc<dyn CredentialSource>> {
        let current = scope::require_present(
            self.read(&record.binding.alias)?,
            "remote binding",
            "Connect this machine with se remote add using its saved name.",
        )?;
        if current.sha256 != record.sha256 {
            return Err(scope::unreadable(
                "remote binding",
                "binding changed; re-admit the exact alias",
            ));
        }
        let key = ProtectedCredential::open(
            self.files.clone(),
            self.key_path(&record.binding.paired.grant),
        )?;
        if key.credential_sha256() != current.binding.credential_sha256.0 {
            return Err(scope::unreadable(
                "remote binding",
                "protected credential differs from the saved machine session",
            ));
        }
        Ok(Arc::new(BoundCredential {
            records: self.clone(),
            alias: record.binding.alias.clone(),
            expected: record.binding.clone(),
            key,
        }))
    }
}
fn alias_name(alias: &str) -> Result<()> {
    if alias.is_empty()
        || alias.len() > 64
        || !alias
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
    {
        return Err(se_types::SeError::invalid(
            "remote alias",
            "1..64 ASCII letters, digits, hyphens or underscores",
        ));
    }
    Ok(())
}
fn validate(binding: &SavedBinding) -> Result<()> {
    alias_name(&binding.alias)?;
    RemoteRoute {
        #[cfg(feature = "remote")]
        forward: None,
        address: binding.route,
        host: binding.paired.host,
    }
    .validate()?;
    binding.paired.scope.validate()?;
    if let Some(forward) = &binding.forward {
        forward.validate()?;
        if forward.local != binding.route {
            return Err(scope::unreadable(
                "remote binding",
                "saved routing and SSH forward addresses differ",
            ));
        }
    }
    if binding.paired.authority_revision == 0
        || binding
            .forward
            .as_ref()
            .is_none_or(|f| f.host != binding.paired.host)
    {
        return Err(scope::unreadable(
            "remote binding",
            "machine identity or authority revision differs",
        ));
    }
    Ok(())
}

impl ProtectedBindings {
    pub(crate) fn forget(&self, binding: &SavedBinding, expected: [u8; 32]) -> Result<()> {
        let current = scope::require_present(
            self.read(&binding.alias)?,
            "saved machine",
            "Read the disconnected record before forgetting it.",
        )?;
        if current.sha256 != expected || current.binding.connected {
            return Err(scope::unreadable(
                "saved machine",
                "record changed while disconnecting",
            ));
        }
        // Remove the public routing record first. A failed credential removal
        // leaves an explicit orphan, never an active route to missing credentials.
        self.files
            .remove_owned(&self.path(&binding.alias)?, expected)
            .map_err(|e| se_core::store_error::store_error(&e))?;
        self.files
            .remove_owned(
                &self.key_path(&binding.paired.grant),
                binding.credential_sha256.0,
            )
            .map_err(|e| se_core::store_error::store_error(&e))?;
        self.files
            .remove_owned(
                &self.machine_path(binding.paired.host),
                Sha256::digest(binding.alias.as_bytes()).into(),
            )
            .map_err(|e| se_core::store_error::store_error(&e))?;
        Ok(())
    }
}

impl ProtectedBindings {
    fn machine_path(&self, host: RemoteHostId) -> PathBuf {
        self.root
            .join("remote-bindings")
            .join(format!(".machine-{}.name", host.0.hex()))
    }
    pub(crate) fn check_machine(&self, binding: &SavedBinding) -> Result<()> {
        self.machine_name(binding, false)
    }
    fn claim_machine(&self, binding: &SavedBinding) -> Result<()> {
        self.machine_name(binding, true)
    }
    fn machine_name(&self, binding: &SavedBinding, create: bool) -> Result<()> {
        let path = self.machine_path(binding.paired.host);
        match self
            .files
            .readback(&path)
            .map_err(|e| se_core::store_error::store_error(&e))?
        {
            Read::Absent { .. } if create => self
                .files
                .replace_owned(&path, None, binding.alias.as_bytes())
                .map_err(|e| se_core::store_error::store_error(&e)),
            Read::Absent { .. } => Ok(()),
            read => {
                let mut file = scope::require_present(
                    read,
                    "machine name",
                    "Restore readable protected machine naming before reconnecting.",
                )?;
                let mut bytes = Vec::new();
                file.by_ref()
                    .take(65)
                    .read_to_end(&mut bytes)
                    .map_err(|e| scope::unreadable("machine name", &e.to_string()))?;
                if bytes != binding.alias.as_bytes() {
                    let name = std::str::from_utf8(&bytes).map_err(|_| {
                        scope::unreadable("machine name", "saved name is malformed")
                    })?;
                    alias_name(name).map_err(|_| {
                        scope::unreadable("machine name", "saved name is malformed")
                    })?;
                    return Err(se_types::SeError::invalid(
                        "machine name",
                        &format!(
                            "existing saved name {name}; reuse it or explicitly forget it before choosing another"
                        ),
                    ));
                }
                Ok(())
            }
        }
    }
}

/// A cached client never retains authority after disconnect or forget.
struct BoundCredential {
    records: ProtectedBindings,
    alias: String,
    expected: SavedBinding,
    key: ProtectedCredential,
}
impl CredentialSource for BoundCredential {
    fn credential_sha256(&self) -> [u8; 32] {
        self.key.credential_sha256()
    }
    fn credential(&self) -> Result<LinkSecret> {
        let record = scope::require_present(
            self.records.read(&self.alias)?,
            "machine connection",
            "Explicitly add the saved machine to reconnect.",
        )?;
        if !record.binding.connected || !record.binding.same_authority(&self.expected) {
            return Err(scope::unreadable(
                "machine connection",
                "the saved connection changed or disconnected; admit the current binding before reconnecting",
            ));
        }
        self.key.credential()
    }
}
