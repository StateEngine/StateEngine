//! Native retained-root implementation of Atlas's safe source port. Activation,
//! watches and cache ownership remain with the host's Atlas lifecycle adapter.
use se_atlas::{
    errors::AtlasResult,
    lifecycle::{CaseMode, FileIdentity, RevisionTrust},
    model::{RelativePath, RootRegistration},
    scope::Scope,
    source::{RegisteredSource, SourceAccess, SourceFile},
};
use se_proc::{NativeRootFile, NativeSourceRoot};
use se_types::{Detail, SeError, code::AtlasText, details};
use std::io::{self, Read, Seek, SeekFrom};

pub struct NativeAtlasSource {
    root: NativeSourceRoot,
    case_mode: CaseMode,
}
impl NativeAtlasSource {
    /// Registration and case mode come from the authorized host's physical-root
    /// policy, never a query's path/cwd. Opening is explicit activation work.
    pub fn open(
        registration: RootRegistration,
        case_mode: CaseMode,
    ) -> AtlasResult<RegisteredSource<Self>> {
        let root = NativeSourceRoot::open(&registration.canonical_source_root)
            .map_err(|e| error("registered source root", e))?;
        let identity = root
            .physical_identity()
            .map_err(|e| error("registered source root", e))?;
        let scope = Scope::new(registration, identity)?;
        RegisteredSource::new(scope, Self { root, case_mode })
    }
}
impl SourceAccess for NativeAtlasSource {
    fn physical_root(&self) -> AtlasResult<[u8; 32]> {
        self.root
            .physical_identity()
            .map_err(|e| error("registered source root", e))
    }
    fn case_mode(&self) -> CaseMode {
        self.case_mode
    }
    fn open(&self, path: &RelativePath) -> AtlasResult<Option<Box<dyn SourceFile + '_>>> {
        Ok(self
            .root
            .open_relative(path.as_str())
            .map_err(|e| error(path.as_str(), e))?
            .map(|file| Box::new(PinnedSource(file)) as Box<dyn SourceFile>))
    }
}
struct PinnedSource<'a>(NativeRootFile<'a>);
impl Read for PinnedSource<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.0.read(bytes)
    }
}
impl Seek for PinnedSource<'_> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.0.seek(position)
    }
}
impl SourceFile for PinnedSource<'_> {
    fn identity(&self) -> AtlasResult<FileIdentity> {
        let native = self.0.revision().map_err(|e| error("retained source", e))?;
        Ok(FileIdentity {
            volume: native.volume,
            file: native.file,
            size: native.size,
            mtime_unix_nanos: native.mtime_unix_nanos,
            ctime_unix_nanos: native.ctime_unix_nanos,
            change_sequence: None,
            sequence_domain: None,
            // Native ctime is a useful change filter, not a qualified shortcut.
            revision_trust: RevisionTrust::Unverified,
        })
    }
    fn validate_path(&self) -> AtlasResult<bool> {
        self.0
            .validate_name()
            .map_err(|e| error("retained source", e))
    }
}
fn error(path: &str, error: io::Error) -> SeError {
    SeError::new(Detail::AtlasSourceUnreadable(
        details::AtlasSourceUnreadable {
            path: path.into(),
            reason: error.to_string(),
        },
    ))
    .with_cause(error)
}
