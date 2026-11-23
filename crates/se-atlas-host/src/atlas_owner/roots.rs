//! Registered worktrees from the authoritative catalogue.
use super::*;
use se_core::admission::read_scope;
use se_store::{EventBody, ReadBudget};
use sha2::{Digest, Sha256};
use std::num::NonZeroU32;

/// A paged walk of every registered project.
#[derive(Default)]
pub(super) struct Scan {
    after: Option<se_types::Cursor>,
}

impl Scan {
    /// Register one page of projects. True once the catalogue is exhausted.
    pub(super) fn page(
        &mut self,
        host: &dyn AtlasHost,
        owner: &HumanId,
        service: &Service,
    ) -> Result<bool> {
        let admitted = admission(host, owner, Scope::Registry);
        let phase = host.checked_read_phase()?;
        let mut snapshot = phase
            .into_snapshot(read_scope(&admitted))
            .map_err(|e| store_error(&e))?;
        let read = snapshot
            .projects(ReadBudget {
                page: se_types::PageRequest {
                    after: self.after.clone(),
                    limit: NonZeroU32::new(32)
                        .ok_or_else(|| SeError::invalid("Atlas catalogue", "positive limit"))?,
                    max_bytes: NonZeroU32::new(131_072)
                        .ok_or_else(|| SeError::invalid("Atlas catalogue", "positive byte cap"))?,
                },
                deadline: Duration::from_millis(100),
            })
            .map_err(|e| store_error(&e));
        let page = close_read(read, snapshot.close())?;
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
                    service.register(&project, specs(&project, &roots, &service.home)?)?;
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

/// Each worktree's stable root id and private store directory.
pub(super) fn specs(
    project: &ProjectId,
    roots: &[se_store::Root],
    home: &std::path::Path,
) -> Result<Vec<RootSpec>> {
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
            Ok(RootSpec {
                project: project.clone(),
                directory: home.join(project.as_str()).join(id.as_str()),
                root: id,
                source,
            })
        })
        .collect()
}
