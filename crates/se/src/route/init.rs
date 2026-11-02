//! Explicit setup owns absent-store creation and finishes missing durable facts
//! on retry. No repository file or Git state is changed by ordinary setup.
use super::{
    execute,
    files::{DirectLease, Files},
    owner, select, setup,
};
use crate::bootstrap::Bootstrap;
use se_core::{
    admission::read_scope,
    commit::Cx,
    dispatch::Kernel,
    ops::*,
    scope,
    store_error::{store_error, write_error},
};
use se_store::{
    Actor, Admission, DirectStore, EventBody, LeaseIdentity, LeaseMode, ReadStore, Scope, Snapshot,
    SqliteDirect, SqliteFactory, StateFiles, StoreFactory, StoreOptions,
};
use se_types::{
    AgentId, HumanId, IdempotencyKey, NativePath, ProjectId, Read, Result, SeError, StoreId,
};
use sha2::{Digest, Sha256};
use std::time::Duration;
#[path = "init/repository.rs"]
mod repository;

fn phase_key(key: &IdempotencyKey, phase: &str) -> Result<IdempotencyKey> {
    let digest: String = se_types::hex_lower(&Sha256::digest(
        serde_json::to_vec(key).map_err(|e| scope::unreadable("setup key", &e.to_string()))?,
    ));
    IdempotencyKey::new(format!("init.{phase}.{digest}"))
}
fn present<R: ReadStore>(store: &R, admission: &Admission, actor: Actor) -> Result<bool> {
    let mut snap = store
        .snapshot(read_scope(admission))
        .map_err(|e| store_error(&e))?;
    let found = snap.principal(actor).map_err(|e| store_error(&e));
    let closed = snap.close().map_err(|e| store_error(&e));
    let found = found?;
    closed?;
    match found {
        Read::Present { .. } => Ok(true),
        Read::Absent { .. } => Ok(false),
        Read::Unreadable { source, reason, .. } => Err(scope::unreadable(&source, &reason)),
        Read::Unknown { what } => Err(scope::unreadable("setup principal", &what)),
    }
}
fn append(
    store: &mut SqliteDirect,
    lease: &DirectLease,
    batch: se_store::AtomicBatch,
    changed: &mut Vec<String>,
) -> Result<se_store::CommitReceipt> {
    let key = batch.request.as_ref().map(|r| r.key.clone());
    let receipt = store
        .append(batch, lease)
        .map_err(|e| write_error(&e, "project.init", key.as_ref(), &[]))?;
    if receipt.durability != se_store::CommitDurability::Full {
        return Err(scope::unreadable(
            "setup publication",
            "identity registration did not return FULL durability",
        ));
    }
    if receipt.maintenance_pending {
        changed
            .push("committed setup facts; storage checkpoint maintenance remains pending".into());
    }
    Ok(receipt)
}
pub fn execute(cx: &Bootstrap, input: ProjectInit) -> Result<AnyOutput> {
    if cx.session.is_some() {
        return Err(SeError::new(se_types::Detail::OwnerRequired(
            se_types::details::OwnerRequired {
                op: "project.init".into(),
            },
        )));
    }
    let repository = repository::observe(cx, &input)?;
    if input.launch {
        return Err(SeError::new(se_types::Detail::FeatureUnavailable(se_types::details::FeatureUnavailable {
            subject:"agent launch".into(), reason:"launching agents isn't available in this build yet".into(), next_step:"Use se init without --launch to save the project, then inspect it with se status.".into(),
        })));
    }
    if input.adopt {
        return Err(SeError::new(se_types::Detail::FeatureUnavailable(
            se_types::details::FeatureUnavailable {
                subject: "user-started provider integrations".into(),
                reason:
                    "installing unmanaged-session integrations isn't available in this build yet"
                        .into(),
                next_step:
                    "Use se init without --adopt for managed setup without repository changes."
                        .into(),
            },
        )));
    }
    // The existing installation claim serializes explicit setup with another
    // setup or installer, independent of environment-selected state homes.
    let _claim = se_proc::NativeInstallationClaim::acquire()
        .map_err(|e| scope::unreadable("setup ownership", &e.to_string()))?;
    let before = setup::inspect(&cx.home, receipt::timestamp(execute::now_us()?)?)?;
    let observed = match &before {
        setup::Setup::Absent(_) => owner::observe(&[])?,
        setup::Setup::Present(reader) => {
            let files = Files::open(&cx.home).map_err(|e| store_error(&e))?;
            owner::from_inventory(&owner::inventory(reader, &files)?)?
        }
    };
    observed.authorize("project.init", observed.os_owner(), false, false)?;
    let files = Files::create(&cx.home).map_err(|e| store_error(&e))?;
    match &before {
        setup::Setup::Present(_) => {
            super::identity::require_machine(&files)?;
            super::credential::require(&files)?;
        }
        setup::Setup::Absent(_) => {
            super::identity::initialize_machine(&files)?;
            super::credential::initialize(&files)?;
        }
    }
    let lock = cx.home.join("runtime.lock");
    match files.readback(&lock).map_err(|e| store_error(&e))? {
        Read::Absent { .. } => {
            let staged = files
                .create_staging(&cx.home)
                .map_err(|e| store_error(&e))?;
            staged
                .file
                .sync_all()
                .map_err(|e| scope::unreadable("setup runtime lock", &e.to_string()))?;
            drop(staged.file);
            match files.publish_no_replace(&staged.path, &lock) {
                Ok(()) => (),
                Err(error) if error.code == se_store::StoreErrorCode::AlreadyExists => files
                    .retire_staging(&staged.path, Sha256::digest([]).into())
                    .map_err(|e| store_error(&e))?,
                Err(error) => return Err(store_error(&error)),
            }
        }
        Read::Present { .. } => (),
        Read::Unreadable { source, reason, .. } => return Err(scope::unreadable(&source, &reason)),
        Read::Unknown { what } => return Err(scope::unreadable("runtime lock", &what)),
    }
    let existing_store = match &before {
        setup::Setup::Present(reader) => Some(reader.info().map_err(|e| store_error(&e))?.id),
        setup::Setup::Absent(_) => None,
    };
    let mut lease = DirectLease::acquire(
        files,
        &lock,
        LeaseIdentity {
            store: existing_store,
            generation: 1,
            mode: LeaseMode::DirectClient,
        },
    )
    .map_err(|e| store_error(&e))?
    .ok_or_else(|| {
        SeError::new(se_types::Detail::StateConflict(
            se_types::details::StateConflict {
                subject: "setup writer".into(),
                reason: "the live host holds the writer lease".into(),
                next_step: "Run se down with the same --home, then retry se init".into(),
            },
        ))
    })?;
    let options = StoreOptions {
        state_directory: cx.home.clone(),
        busy_timeout: Duration::from_millis(250),
    };
    let mut store =
        match SqliteFactory::open_direct(&options, &lease).map_err(|e| store_error(&e))? {
            Read::Present { value } => value,
            Read::Absent { .. } => {
                let id =
                    StoreId::from_bytes(execute::facts()?.message.canonical_bytes()?.ok_or_else(
                        || SeError::invalid("store identity", "fresh canonical UUID"),
                    )?)?;
                SqliteFactory::create_direct(&options, &lease, id).map_err(|e| store_error(&e))?
            }
            Read::Unreadable { source, reason, .. } => {
                return Err(scope::unreadable(&source, &reason));
            }
            Read::Unknown { what } => return Err(scope::unreadable("setup store", &what)),
        };
    lease.identity.store = Some(store.info().map_err(|e| store_error(&e))?.id);
    let result = registration::finish(cx, &input, &repository, &observed, &mut store, &lease);
    let closed = store.close().map_err(|e| store_error(&e));
    match result {
        Ok(value) => {
            closed?;
            Ok(value)
        }
        Err(error) => Err(match closed {
            Ok(()) => error,
            Err(close) => error.with_cause(close),
        }),
    }
}

#[path = "init/agent.rs"]
mod agent_setup;
#[path = "init/registration.rs"]
mod registration;
