//! Explicit setup owns absent-store creation and finishes missing durable facts
//! on retry. Detected harnesses receive the shared project MCP configuration.
use super::{
    execute,
    files::{DirectLease, Files},
    first_init, owner, select, setup,
};
use crate::bootstrap::Bootstrap;
use se_config::config_policy::ConfigFile;
use se_core::{
    commit::Cx,
    dispatch::Kernel,
    ops::*,
    scope,
    store_error::{store_error, write_error},
};
use se_store::{
    Actor, Admission, DirectStore, EventBody, LeaseIdentity, LeaseMode, ReadStore, Scope, Snapshot,
    SqliteDirect, SqliteFactory, StoreFactory, StoreInfo, StoreOptions,
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
fn mcp_setup_error(mut error: SeError) -> SeError {
    error.body = error.body.with_remedy(se_types::Remedy {
        text: "Project registration was saved. Resolve the reported MCP configuration issue, then retry se init.".into(),
        command: None,
    });
    error
}
fn present<R: ReadStore>(store: &R, admission: &Admission, actor: Actor) -> Result<bool> {
    let mut snap = super::select::open_snapshot(store, admission)?;
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
    if receipt.maintenance_failed {
        changed
            .push("committed setup facts; storage checkpoint maintenance remains pending".into());
    }
    Ok(receipt)
}
fn prepare_input(
    cx: &Bootstrap,
    input: &mut ProjectInit,
) -> Result<(
    ConfigFile,
    repository::Repository,
    Option<super::adoption::Plan>,
)> {
    if cx.session.is_some() {
        return Err(SeError::new(se_types::Detail::OwnerRequired(
            se_types::details::OwnerRequired {
                op: "project.init".into(),
            },
        )));
    }
    let configuration = super::harness_setup::prepare(cx, input)?;
    if input.harness.is_some() {
        let binding = se_core::harness_selection::resolve(
            &configuration,
            input.provider,
            input.harness.as_deref(),
        )?;
        input.provider = Some(binding.provider);
        input.harness = binding.harness;
    }
    if input.adopt && input.harness.is_some() {
        return Err(SeError::invalid(
            "harness adoption",
            "named protocol descriptors launch managed sessions; choose Claude Code or Codex for adoption",
        ));
    }
    let repository = repository::observe(cx, input)?;
    if input.launch {
        return Err(SeError::new(se_types::Detail::FeatureUnavailable(
            se_types::details::FeatureUnavailable {
                subject: "init --launch".into(),
                reason: "combined registration and launch is not supported in this build".into(),
                next_step:
                    "Run se init without --launch, then run its printed first-launch command."
                        .into(),
            },
        )));
    }
    let adoption = input
        .adopt
        .then(|| super::adoption::prepare(cx, input))
        .transpose()?;
    Ok((configuration, repository, adoption))
}
fn acquire_setup_lease(cx: &Bootstrap) -> Result<DirectLease> {
    // Ordinary setup changes only this state home. Its no-replace publication
    // and direct writer lease coordinate setup without blocking other homes
    // behind an unrelated account-wide install or PATH edit.
    let before = setup::inspect_for_init(&cx.home, receipt::timestamp(execute::now_us()?)?, false)?;
    let observed = match &before {
        setup::Setup::Absent(_) => owner::observe(&[])?,
        setup::Setup::Present(reader) => {
            let files = Files::open(&cx.home).map_err(|e| store_error(&e))?;
            owner::from_inventory(&owner::inventory(reader, &files)?)?
        }
    };
    observed.authorize("project.init", observed.os_owner(), false, false)?;
    let files = Files::create(&cx.home).map_err(|e| store_error(&e))?;
    drop(before);
    DirectLease::acquire_setup(
        files,
        LeaseIdentity { store: None, generation: 1, mode: LeaseMode::DirectClient },
    )
    .map_err(|e| store_error(&e))?
    .ok_or_else(|| SeError::new(se_types::Detail::StateConflict(
        se_types::details::StateConflict {
            subject: "setup writer".into(),
            reason: "another setup, removal, uninstall or runtime holds this home's lease".into(),
            next_step: "Wait for that operation, or run se down with the same --home, then retry se init".into(),
        },
    )))
}
fn reobserve_after_exclusion(
    cx: &Bootstrap,
    lease: &mut DirectLease,
    quarantined: bool,
) -> Result<(owner::FileOwner, setup::Setup)> {
    let before = setup::inspect_for_init(
        &cx.home,
        receipt::timestamp(execute::now_us()?)?,
        quarantined,
    )?;
    let files = &lease.files;
    first_init::resumable(files)?;
    let observed = match &before {
        setup::Setup::Absent(_) => owner::observe(&[])?,
        setup::Setup::Present(reader) => owner::from_inventory(&owner::inventory(reader, files)?)?,
    };
    observed.authorize("project.init", observed.os_owner(), false, false)?;
    lease.identity.store = match &before {
        setup::Setup::Present(reader) => Some(reader.info().map_err(|e| store_error(&e))?.id),
        setup::Setup::Absent(_) => None,
    };
    Ok((observed, before))
}
fn establish_identity_and_credentials(files: &Files, before: &setup::Setup) -> Result<()> {
    match before {
        setup::Setup::Present(reader) => {
            super::identity::require_machine(files)?;
            match super::credential::read(files)? {
                Read::Absent { .. } => {
                    let inventory = owner::inventory(reader, files)?;
                    let [human] = inventory.owners.as_slice() else {
                        return Err(scope::unreadable(
                            "explicit setup credential",
                            "one retained protected owner is required",
                        ));
                    };
                    let admitted = Admission {
                        actor: Actor::Human(human.clone()),
                        scope: Scope::Registry,
                        session: None,
                        generation: 1,
                    };
                    // Explicit init can establish a fresh key after Remove --all,
                    // only with no projects, host or direct writer. Automatic
                    // startup still requires the original key and never repairs it.
                    super::empty_home::verify(files, reader, &admitted, Duration::from_secs(5))?;
                    super::credential::initialize(files)?;
                }
                Read::Present { .. } => (),
                other => {
                    scope::require_present(
                        other,
                        "explicit setup credential",
                        "Restore access to the original credential; unreadable state cannot become a new key.",
                    )?;
                }
            }
        }
        setup::Setup::Absent(_) => {
            super::identity::initialize_machine(files)?;
            super::credential::initialize_before_publish(files, |secret| {
                first_init::prepare(files, secret)
            })?;
        }
    }
    Ok(())
}
fn open_setup_store(cx: &Bootstrap, lease: &mut DirectLease) -> Result<(SqliteDirect, StoreInfo)> {
    let options = StoreOptions {
        state_directory: cx.home.clone(),
        busy_timeout: Duration::from_millis(250),
    };
    let store =
        match SqliteFactory::open_direct(&options, lease).map_err(|e| store_error(&e))? {
            Read::Present { value } => value,
            Read::Absent { .. } => {
                let id =
                    StoreId::from_bytes(execute::facts()?.message.canonical_bytes()?.ok_or_else(
                        || SeError::invalid("store identity", "fresh canonical UUID"),
                    )?)?;
                SqliteFactory::create_direct(&options, lease, id).map_err(|e| store_error(&e))?
            }
            Read::Unreadable { source, reason, .. } => {
                return Err(scope::unreadable(&source, &reason));
            }
            Read::Unknown { what } => return Err(scope::unreadable("setup store", &what)),
        };
    let info = store.info().map_err(|e| store_error(&e))?;
    lease.identity.store = Some(info.id.clone());
    Ok((store, info))
}
pub fn execute(cx: &Bootstrap, mut input: ProjectInit) -> Result<AnyOutput> {
    let (configuration, repository, adoption) = prepare_input(cx, &mut input)?;
    let mut lease = acquire_setup_lease(cx)?;
    // Preserve strict no-follow staging names under exclusive home custody.
    let recovered_changes = setup::quarantine(&lease.files)?;
    // Re-read after exclusion: another setup or removal may have completed
    // between the preliminary owner check and acquisition of this home.
    let (observed, before) =
        reobserve_after_exclusion(cx, &mut lease, !recovered_changes.is_empty())?;
    establish_identity_and_credentials(&lease.files, &before)?;
    let (mut store, info) = open_setup_store(cx, &mut lease)?;
    let files = &lease.files;
    let result = first_init::complete(files, &info).and_then(|()| {
        registration::finish(
            cx,
            registration::Plan {
                input: &input,
                repository: &repository,
                configuration: &configuration,
            },
            &observed,
            &mut store,
            &lease,
            recovered_changes,
        )
    });
    let closed = store.close().map_err(|e| store_error(&e));
    match result {
        Ok(mut value) => {
            closed?;
            if let Some(plan) = adoption {
                super::adoption::install(cx, &repository.path, plan, &mut value)?;
            }
            // Harness health checks may start the host; release setup custody first.
            drop(lease);
            let AnyOutput::ProjectInit(output) = &mut value else {
                return Err(SeError::invalid(
                    "setup result",
                    "the committed project setup output",
                ));
            };
            let alternate_home = (crate::bootstrap::default_home().ok().as_ref() != Some(&cx.home))
                .then_some(cx.home.as_path());
            output.value.changed.extend(
                se_host::provider_mcp::configure(&repository.path, &configuration, alternate_home)
                    .map_err(mcp_setup_error)?,
            );
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
