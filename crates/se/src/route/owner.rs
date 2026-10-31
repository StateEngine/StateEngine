//! Native observations cross into core policy here, without a caller-selected OS identity.
use se_core::admission::{AgentTreeCheck, OwnerObservations, authorize_file_owner};
use se_proc::{NativeOwner, ProcessRecord};
use se_store::{OwnerGuardInventory, ReadBudget, ReadStore, StateFiles};
use se_types::{Detail, Result, SeError, details};
use std::{num::NonZeroU32, time::Duration};

/// The protected pre-admission reader either yields every unresolved home-wide
/// record or refuses. Native decoding and the owner probe happen after it has
/// closed the read transaction; no Owner visibility is assumed to establish Owner.
pub fn inventory<R: ReadStore>(store: &R, files: &dyn StateFiles) -> Result<OwnerGuardInventory> {
    store
        .owner_guard(
            files,
            ReadBudget {
                page: se_types::PageRequest {
                    after: None,
                    limit: NonZeroU32::new(1000).ok_or_else(|| {
                        SeError::invalid("owner inventory", "positive item budget")
                    })?,
                    max_bytes: NonZeroU32::new(2 * 1024 * 1024).ok_or_else(|| {
                        SeError::invalid("owner inventory", "positive byte budget")
                    })?,
                },
                deadline: Duration::from_secs(5),
            },
        )
        .map_err(|error| se_core::store_error::store_error(&error))
}

pub struct FileOwner {
    observed: OwnerObservations,
    session_present: bool,
}
impl FileOwner {
    pub fn os_owner(&self) -> &str {
        &self.observed.os_owner
    }
    pub fn authorize(
        &self,
        operation: &str,
        expected_owner: &str,
        session_present: bool,
        human_only: bool,
    ) -> Result<()> {
        authorize_file_owner(
            operation,
            expected_owner,
            session_present || self.session_present,
            human_only,
            &self.observed,
        )
    }
}
/// `records` must be the complete successful home-wide custody read, including
/// unresolved native records. The route may supply [] only after measured store
/// absence or a successful empty inventory; endpoint absence never supplies it.
pub fn observe(records: &[ProcessRecord]) -> Result<FileOwner> {
    let observed = se_proc::observe_owner_self(records).map_err(|error| {
        se_core::scope::unreadable("native owner self-check", &error.to_string())
    })?;
    let owner = match observed.owner() {
        NativeOwner::Unix {
            real_uid,
            effective_uid,
        } => {
            if real_uid != effective_uid {
                return Err(SeError::new(Detail::OsUserMismatch(
                    details::OsUserMismatch {
                        expected: real_uid.to_string(),
                        actual: effective_uid.to_string(),
                    },
                )));
            }
            effective_uid.to_string()
        }
        NativeOwner::Windows { sid } => sid.clone(),
    };
    let agent_tree = match observed.agent_trees().first() {
        None => AgentTreeCheck::Outside,
        Some(found) => AgentTreeCheck::Inside {
            record: format!("record {} ({:?})", found.record_index, found.basis),
        },
    };
    Ok(FileOwner {
        observed: OwnerObservations {
            os_owner: owner,
            agent_tree,
            stdin_console: observed.stdin_console(),
            stdout_console: observed.stdout_console(),
            provider_marker: observed.provider_marker_present(),
        },
        session_present: observed.session_present(),
    })
}
