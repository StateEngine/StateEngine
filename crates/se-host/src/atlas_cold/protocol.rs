use super::*;
use se_types::{NativePath, ProjectId};
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    #[serde(default)]
    pub history_unavailable: Option<se_types::ErrorBody>,
    pub job: AtlasJobId,
    pub project: ProjectId,
    pub root: RootId,
    pub source_root: NativePath,
    pub home: NativePath,
    pub physical_root: [u8; 32],
    pub expected_epoch: Option<CacheEpoch>,
    pub epoch: CacheEpoch,
    pub max_files: u32,
    pub ignore_digest: ContentHash,
    pub global_patterns: Vec<String>,
    pub generated_prefixes: Vec<RelativePath>,
}
impl Request {
    pub fn validate(&self) -> AtlasResult<()> {
        if self.max_files == 0
            || self.max_files > 100_000
            || self.generated_prefixes.len() > 32
            || self.global_patterns.iter().map(String::len).sum::<usize>()
                + self
                    .generated_prefixes
                    .iter()
                    .map(|p| p.as_str().len())
                    .sum::<usize>()
                > 32768
            || self.expected_epoch.as_ref() == Some(&self.epoch)
        {
            return Err(failure("bounded cold request with a fresh epoch required"));
        }
        Ok(())
    }
    pub fn source(&self) -> AtlasResult<RegisteredSource<NativeAtlasSource>> {
        let registration = RootRegistration {
            project: self.project.clone(),
            root: self.root.clone(),
            canonical_source_root: self.source_root.to_local()?,
            cache: CacheLocation {
                directory: self
                    .home
                    .to_local()?
                    .join(self.project.as_str())
                    .join(self.root.as_str()),
            },
            git_metadata: None,
        };
        let source = NativeAtlasSource::open(
            registration,
            if cfg!(windows) {
                CaseMode::InsensitivePreserving
            } else {
                CaseMode::Sensitive
            },
        )?;
        if source.scope.physical_root != self.physical_root {
            return Err(failure("registered source physical identity changed"));
        }
        Ok(source)
    }
}
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub enum Phase {
    Startup,
    Discovery,
    SourceRead,
    Parse,
    Resolve,
    Verify,
    Commit,
    Checkpoint,
    Finalize,
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum Reply {
    Working {
        job: AtlasJobId,
        path: Option<RelativePath>,
        phase: Phase,
    },
    Progress {
        job: AtlasJobId,
        discovered: u64,
        completed: u64,
    },
    Completed {
        job: AtlasJobId,
        summary: Box<IndexSummary>,
    },
    Failed {
        job: AtlasJobId,
        error: se_types::ErrorBody,
    },
}
