use super::*;
use se_core::admission::read_scope;
use se_store::{EventBody, ReadBudget};
use sha2::{Digest, Sha256};
use std::{io::Read, num::NonZeroU32};
#[derive(Default)]
pub(super) struct Scan {
    after: Option<se_types::Cursor>,
}
impl Scan {
    /// Stream the authoritative catalogue into disk metadata. No project count
    /// becomes an in-memory registration or a native watch admission limit.
    pub(super) fn page(
        &mut self,
        context: &ExecutionContext,
        owner: &HumanId,
        home: &std::path::Path,
        work: &ProjectWork,
    ) -> Result<bool> {
        let admitted = admission(context, owner, Scope::Registry);
        let phase = executor::checked_pooled_phase(&context.reads, context.generation)?;
        let mut snapshot = phase
            .into_snapshot(read_scope(&admitted))
            .map_err(|e| store_error(&e))?;
        let read = snapshot
            .projects(ReadBudget {
                page: se_types::PageRequest {
                    after: self.after.clone(),
                    limit: NonZeroU32::new(32)
                        .ok_or_else(|| SeError::invalid("Atlas catalogue", "positive limit"))?,
                    max_bytes: NonZeroU32::new(131072)
                        .ok_or_else(|| SeError::invalid("Atlas catalogue", "positive byte cap"))?,
                },
                deadline: Duration::from_millis(100),
            })
            .map_err(|e| store_error(&e));
        let page = executor::close_read(read, snapshot.close())?;
        let complete = page.window().complete();
        self.after = page.next().cloned();
        if !complete && self.after.is_none() {
            return Err(SeError::invalid(
                "Atlas catalogue",
                "a continuation for an incomplete page",
            ));
        }
        for record in page.into_items() {
            match record.current.body {
                EventBody::ProjectRegistered { project, roots, .. }
                | EventBody::ProjectUpdated { project, roots, .. } => {
                    work.register(&project, registrations(&project, &roots, home)?)?;
                }
                _ => {
                    return Err(SeError::invalid(
                        "Atlas catalogue",
                        "a committed active project head",
                    ));
                }
            }
        }
        Ok(complete)
    }
}
pub(super) fn registrations(
    project: &ProjectId,
    roots: &[se_store::Root],
    home: &std::path::Path,
) -> Result<Vec<RootRegistration>> {
    roots
        .iter()
        .map(|root| {
            let mut digest = Sha256::new();
            digest.update(b"StateEngine Atlas root v1\0");
            digest.update(project.as_str().as_bytes());
            digest.update(&root.canonical_key);
            let hash = digest.finalize();
            let mut entropy = [0; 10];
            entropy.copy_from_slice(&hash[..10]);
            let id = RootId::from_parts(1, entropy)?;
            let source = root.path.to_local()?;
            if !source.is_absolute() {
                return Err(SeError::invalid(
                    "Atlas root",
                    "an absolute committed native root",
                ));
            }
            Ok(RootRegistration {
                project: project.clone(),
                root: id.clone(),
                canonical_source_root: source,
                cache: CacheLocation {
                    directory: home.join(project.as_str()).join(id.as_str()),
                },
                git_metadata: None,
            })
        })
        .collect()
}
pub(super) fn policy(enabled: bool) -> AtlasPolicy {
    AtlasPolicy {
        enabled,
        max_files: 100_000,
        max_change_rows: 50_000,
        change_retention_days: 30,
        max_cache_bytes: 512_000_000,
        total_reserved_bytes: ANONYMOUS_BYTES,
        parse: ParseBudget {
            max_source_bytes: 524288,
            max_rows: 65536,
            max_work: Duration::from_millis(200),
            reserved_bytes: PARSER_BYTES,
        },
        ignore: IgnorePolicy {
            global_patterns: vec!["target/".into(), "node_modules/".into()],
            generated_prefixes: Vec::new(),
            digest: ContentHash(
                Sha256::digest(b"Atlas defaults v1: target/,node_modules/,private-path-denial-v1")
                    .into(),
            ),
        },
        watch: WatchBudget {
            max_directories: 1024,
            max_mapping_bytes: 16384,
            observed_os_limit: None,
        },
    }
}
pub(super) fn git(root: &std::path::Path) -> Result<Option<GitMetadataRegistration>> {
    let source = se_proc::NativeSourceRoot::open(root).map_err(native)?;
    let git = match source.open_directory(".git") {
        Ok(Some(_)) => root.join(".git"),
        Ok(None) => return Ok(None),
        Err(e) if e.kind() == std::io::ErrorKind::NotADirectory => {
            let Some(mut file) = source.open_relative(".git").map_err(native)? else {
                return Ok(None);
            };
            let mut text = String::new();
            (&mut file)
                .take(4097)
                .read_to_string(&mut text)
                .map_err(native)?;
            if text.len() > 4096 || !file.validate_name().map_err(native)? {
                return Err(SeError::invalid(
                    "Git metadata",
                    "a stable bounded .git pointer",
                ));
            }
            let spelling = text
                .trim()
                .strip_prefix("gitdir: ")
                .ok_or_else(|| SeError::invalid("Git metadata", "a gitdir pointer"))?;
            root.join(spelling).canonicalize().map_err(native)?
        }
        Err(e) => return Err(native(e)),
    };
    let git_root = se_proc::NativeSourceRoot::open(&git).map_err(native)?;
    let common = if let Some(mut file) = git_root.open_relative("commondir").map_err(native)? {
        let mut text = String::new();
        (&mut file)
            .take(4097)
            .read_to_string(&mut text)
            .map_err(native)?;
        if text.len() > 4096 || !file.validate_name().map_err(native)? {
            return Err(SeError::invalid(
                "Git metadata",
                "a stable bounded common-directory pointer",
            ));
        }
        git.join(text.trim()).canonicalize().map_err(native)?
    } else {
        git.clone()
    };
    let common_root = se_proc::NativeSourceRoot::open(&common).map_err(native)?;
    Ok(Some(GitMetadataRegistration {
        physical_git_directory: git,
        physical_common_directory: common,
        git_directory_identity: git_root.physical_identity().map_err(native)?,
        common_directory_identity: common_root.physical_identity().map_err(native)?,
    }))
}
fn native(error: std::io::Error) -> SeError {
    se_core::scope::unreadable("Atlas registered Git metadata", &error.to_string())
        .with_cause(error)
}
