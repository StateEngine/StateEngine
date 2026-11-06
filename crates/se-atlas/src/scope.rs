//! Trusted registration and stable logical IDs; paths never select another root.
use crate::{errors::AtlasResult, model::*};
use se_types::{SeError, code::AtlasText};
#[derive(Clone, Debug)]
pub struct Scope {
    pub registration: RootRegistration,
    pub physical_root: [u8; 32],
}
impl Scope {
    pub fn new(registration: RootRegistration, physical_root: [u8; 32]) -> AtlasResult<Self> {
        if !registration.canonical_source_root.is_absolute()
            || !registration.cache.directory.is_absolute()
        {
            return Err(SeError::invalid(
                "Atlas registration",
                "host-verified absolute source and cache roots",
            ));
        }
        Ok(Self {
            registration,
            physical_root,
        })
    }
    /// The adapter supplies a filesystem-qualified lookup key. The preserved path
    /// is separate: Unicode lowercase is not a substitute for native case policy.
    pub fn file_id(&self, normalized_path_key: &RelativePath) -> FileId {
        let digest = digest(&[
            self.registration.root.as_str().as_bytes(),
            normalized_path_key.as_str().as_bytes(),
        ]);
        let mut key = [0; 16];
        key.copy_from_slice(&digest[..16]);
        FileId(key)
    }
    pub fn child_symbol_id(
        &self,
        file: FileId,
        parent: Option<SymbolId>,
        kind: &str,
        name: &str,
        ordinal: u32,
    ) -> SymbolId {
        let parent = parent.map(|p| p.0);
        SymbolId(digest(&[
            b"atlas-child-v1",
            self.registration.root.as_str().as_bytes(),
            &file.0,
            parent.as_ref().map_or(&[][..], |p| p.as_slice()),
            kind.as_bytes(),
            name.as_bytes(),
            &ordinal.to_be_bytes(),
        ]))
    }
    pub fn symbol_id(
        &self,
        file: FileId,
        kind: &str,
        chain: &[&str],
        name: &str,
        ordinal: u32,
    ) -> SymbolId {
        let mut hash = blake3::Hasher::new();
        for part in [
            self.registration.root.as_str().as_bytes(),
            &file.0,
            kind.as_bytes(),
        ] {
            field(&mut hash, part);
        }
        // A count separates an enclosing chain from the declaration's own name.
        field(&mut hash, &(chain.len() as u64).to_be_bytes());
        for part in chain {
            field(&mut hash, part.as_bytes());
        }
        field(&mut hash, name.as_bytes());
        field(&mut hash, &ordinal.to_be_bytes());
        SymbolId(*hash.finalize().as_bytes())
    }
}
fn field(hash: &mut blake3::Hasher, bytes: &[u8]) {
    hash.update(&(bytes.len() as u64).to_be_bytes());
    hash.update(bytes);
}
fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    for part in parts {
        field(&mut hash, part);
    }
    *hash.finalize().as_bytes()
}
