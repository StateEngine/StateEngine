//! Per-file parsing on the existing private Atlas channel.
use super::*;
use se_types::{NativePath, ProjectId};
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub parse_only: bool,
    pub project: ProjectId,
    pub root: RootId,
    pub source_root: NativePath,
    pub cache_directory: NativePath,
    pub physical_root: [u8; 32],
    pub path: RelativePath,
    pub identity: FileIdentity,
    pub content_hash: ContentHash,
    pub language: Language,
    pub budget: ParseBudget,
    pub profile: ParserProfile,
}
impl Request {
    pub fn source(&self) -> AtlasResult<Source> {
        let registration = RootRegistration {
            project: self.project.clone(),
            root: self.root.clone(),
            canonical_source_root: self.source_root.to_local()?,
            cache: CacheLocation {
                directory: self.cache_directory.to_local()?,
            },
            git_metadata: None,
        };
        let source = crate::atlas_source::NativeAtlasSource::open(
            registration,
            if cfg!(windows) {
                CaseMode::InsensitivePreserving
            } else {
                CaseMode::Sensitive
            },
        )?;
        if source.scope.physical_root != self.physical_root {
            return Err(failure("parse source physical identity changed"));
        }
        Ok(source)
    }
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "row", deny_unknown_fields)]
pub(super) enum Reply {
    Start {
        file: FileId,
        language: Language,
        hash: ContentHash,
        coverage: FileCoverage,
    },
    Symbol(SymbolRecord),
    Import(ImportRecord),
    Reference(ParsedReference),
    Scope(LexicalScope),
    Failed {
        error: se_types::ErrorBody,
    },
    Done,
}
