//! Fixture scope is verified before candidate admission, never by filtering hits.
//! Manifest validation belongs to this experiment adapter, not the product query.
use se_atlas::cache::connection::CacheConnection;
use se_types::code::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::Read,
    path::PathBuf,
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceScope {
    version: u8,
    path_prefixes: Vec<String>,
    tracked_only: bool,
    apply_before_ranking: bool,
}
#[derive(Deserialize)]
#[serde(untagged)]
pub enum Mapping {
    WholeRoot(PathBuf),
    Scoped {
        cache_home: PathBuf,
        epoch: CacheEpoch,
        corpus_revision: String,
        manifest: PathBuf,
        manifest_sha256: String,
    },
}
pub struct Prepared {
    pub home: PathBuf,
    pub query: SearchScope,
    epoch: Option<CacheEpoch>,
    tracked: Option<BTreeSet<String>>,
    expected: usize,
}
impl Mapping {
    pub fn prepare(self, scope: Option<&SourceScope>, revision: &str) -> Result<Prepared> {
        match (self, scope) {
            (Self::WholeRoot(home), None) => Ok(Prepared {
                home,
                query: SearchScope {
                    paths: vec![],
                    languages: vec![],
                },
                epoch: None,
                tracked: None,
                expected: 0,
            }),
            (
                Self::Scoped {
                    cache_home,
                    epoch,
                    corpus_revision,
                    manifest,
                    manifest_sha256,
                },
                Some(scope),
            ) => {
                if scope.version != 1
                    || !scope.tracked_only
                    || !scope.apply_before_ranking
                    || corpus_revision != revision
                    || scope.path_prefixes.is_empty()
                {
                    return Err("unsupported/foreign captured source scope".into());
                }
                let query = SearchScope {
                    paths: scope
                        .path_prefixes
                        .iter()
                        .map(|prefix| {
                            RelativePath::new(
                                prefix
                                    .strip_suffix('/')
                                    .ok_or("directory prefix lacks its boundary")?,
                            )
                            .map_err(Into::into)
                        })
                        .collect::<Result<Vec<_>>>()?,
                    languages: vec![],
                };
                query.validate()?;
                let mut bytes = Vec::new();
                std::fs::File::open(manifest)?
                    .take(2_000_001)
                    .read_to_end(&mut bytes)?;
                if bytes.len() > 2_000_000 {
                    return Err("tracked-source manifest exceeds 2 MB experiment bound".into());
                }
                let digest = Sha256::digest(&bytes)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                if digest != manifest_sha256 {
                    return Err("tracked-source manifest bytes changed".into());
                }
                let paths: Vec<RelativePath> = serde_json::from_slice(&bytes)?;
                if paths.len() > 100_000 || paths.iter().any(|p| !query.includes_path(p)) {
                    return Err("manifest exceeds its source-scope universe".into());
                }
                let expected = paths
                    .iter()
                    .filter(|p| !se_atlas::policy::built_in_denied(p))
                    .count();
                let count = paths.len();
                let tracked = paths
                    .into_iter()
                    .map(|p| p.as_str().to_owned())
                    .collect::<BTreeSet<_>>();
                if tracked.len() != count {
                    return Err("duplicate tracked source path".into());
                }
                Ok(Prepared {
                    home: cache_home,
                    query,
                    epoch: Some(epoch),
                    tracked: Some(tracked),
                    expected,
                })
            }
            _ => {
                Err("scoped qualification requires an epoch-pinned tracked-source manifest".into())
            }
        }
    }
}
impl Prepared {
    pub fn validate_cache(&self, cache: &CacheConnection<'_>) -> Result<()> {
        let Some(tracked) = &self.tracked else {
            return Ok(());
        };
        if self.epoch.as_ref() != Some(&cache.identity().epoch) {
            return Err("prepared cache epoch changed after scope validation".into());
        }
        cache.read(Instant::now()+Duration::from_millis(500), |sql| {
            let mut statement = sql.prepare("SELECT path FROM files WHERE atlas_scope(path,language,?1,x'')")?;
            let mut rows = statement.query([self.query.packed_paths()]).map_err(scope_error)?;
            let mut observed = 0;
            while let Some(row) = rows.next().map_err(scope_error)? {
                let path = row.get::<_,String>(0).map_err(scope_error)?;
                if !tracked.contains(&path) || se_atlas::policy::built_in_denied(&RelativePath::new(path)?) {
                    return Err(scope_error("cache contains an untracked or denied candidate inside the requested scope"));
                }
                observed += 1;
            }
            if observed != self.expected {return Err(scope_error("cache omits ordinary tracked files beyond explicit private-file policy exclusions"));}
            Ok(())
        })?;
        Ok(())
    }
}
fn scope_error(error: impl std::fmt::Display) -> se_types::SeError {
    se_types::SeError::invalid("retrieval source scope", &error.to_string())
}
