//! Owner restore of the newest verified automatic backup. It runs before the
//! ordinary store opening, because the live store may be what is broken; the
//! live store is preserved by the store layer, never repaired.
use super::{execute, files::DirectLease, files::Files, owner, setup};
use crate::bootstrap::Bootstrap;
use se_core::{ops::*, scope, store_error::store_error};
use se_store::{
    Actor, Admission, BackupGeneration, EventBody, IntentDigest, OwnerGuardInventory, ReadScope,
    ReadStore, RecordIdentity, RequestIdentity, Scope, Snapshot, SqliteFactory, SqliteReader,
    StoreFactory, StoreId, StoreOptions, StorePosition, Visibility,
};
use se_types::{HumanId, Read, Result, SeError};
use sha2::{Digest, Sha256};
use std::time::Duration;

struct Live {
    reader: SqliteReader,
    inventory: OwnerGuardInventory,
    head: Option<StorePosition>,
}
pub fn execute(
    cx: &Bootstrap,
    input: StoreRestore,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<AnyOutput> {
    se_core::ops::inputs::Validate::validate(&input)?;
    Ok(run(cx, &input, diagnostic)?.into())
}
fn result(input: &StoreRestore, outcome: &str) -> RestoreResult {
    RestoreResult {
        idempotency_key: input.idempotency_key.clone(),
        outcome: outcome.into(),
        backup: None,
        events_lost: None,
        preserved: None,
        blocking_agents: Vec::new(),
        receipt: None,
        reason: None,
        next: None,
    }
}
fn refused(input: &StoreRestore, reason: &str) -> RestoreResult {
    RestoreResult {
        reason: Some(reason.into()),
        ..result(input, "refused")
    }
}
fn observe_live(
    cx: &Bootstrap,
    files: &Files,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<Option<Live>> {
    let generated_at = receipt::timestamp(execute::now_us()?)?;
    match setup::inspect(&cx.home, generated_at) {
        Ok(setup::Setup::Present(reader)) => Ok(Some(Live {
            inventory: owner::inventory(&reader, files)?,
            head: reader.info().map_err(|e| store_error(&e))?.head,
            reader,
        })),
        Ok(setup::Setup::Absent(_)) => Ok(None),
        Err(error) => {
            diagnostic(&format!(
                "The live store cannot be read ({error}); it will be preserved as it is.\n"
            ))
            .map_err(|e| scope::unreadable("restore diagnostic", &e.to_string()))?;
            Ok(None)
        }
    }
}
fn request(input: &StoreRestore) -> Result<RequestIdentity> {
    let intent = serde_json::json!({"operation":"store.restore","codec_version":1,"arguments":{}});
    let bytes = serde_json::to_vec(&intent)
        .map_err(|e| scope::unreadable("restore intent", &e.to_string()))?;
    Ok(RequestIdentity {
        key: input.idempotency_key.clone(),
        intent: IntentDigest {
            operation: "store.restore",
            codec_version: 1,
            sha256: Sha256::digest(bytes).into(),
        },
    })
}
pub(super) fn newest(options: &StoreOptions) -> Result<Option<BackupGeneration>> {
    let page =
        SqliteFactory::inspect_backups(options, owner::budget()?).map_err(|e| store_error(&e))?;
    Ok(page
        .into_items()
        .into_iter()
        .filter_map(|generation| match generation {
            Read::Present { value } => Some(value),
            _ => None,
        })
        .max_by_key(|generation| generation.through.sequence()))
}
/// Agents with live sessions, by name where the store can still say.
fn agents(reader: &SqliteReader, inventory: &OwnerGuardInventory, owner: &HumanId) -> Vec<String> {
    let name = |project: &se_types::ProjectId, actor: &Actor| -> Option<String> {
        let scope = ReadScope {
            admission: Admission {
                scope: Scope::Project(project.clone()),
                ..admission(owner)
            },
            visibility: Visibility::Owner,
        };
        let record = reader.snapshot(scope).ok()?.principal(actor.clone()).ok()?;
        match record {
            Read::Present { value } => match value.current.body {
                EventBody::PrincipalRegistered { name, .. }
                | EventBody::PrincipalRenamed { name, .. } => Some(name.to_string()),
                _ => None,
            },
            _ => None,
        }
    };
    let mut names: Vec<String> = inventory
        .processes
        .iter()
        .map(|process| {
            let actor = &process.identity.principal;
            let id = match actor {
                Actor::Agent(agent) => agent.to_string(),
                other => format!("{other:?}"),
            };
            match name(&process.project, actor) {
                Some(name) => format!("{name} ({id})"),
                None => id,
            }
        })
        .collect();
    names.sort();
    names.dedup();
    names
}
fn sorted(mut owners: Vec<HumanId>) -> Vec<HumanId> {
    owners.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    owners
}
fn run(
    cx: &Bootstrap,
    input: &StoreRestore,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<RestoreResult> {
    let files = Files::open(&cx.home).map_err(|e| store_error(&e))?;
    let options = StoreOptions {
        state_directory: cx.home.clone(),
        busy_timeout: Duration::from_secs(5),
    };
    let live = observe_live(cx, &files, diagnostic)?;
    let observed = match &live {
        Some(live) => owner::from_inventory(&live.inventory)?,
        // Without a readable store there is no recorded custody to resolve; the
        // terminal, session and provider checks below still apply.
        None => owner::observe(&[])?,
    };
    observed.authorize(
        "store.restore",
        observed.os_owner(),
        cx.session.is_some(),
        true,
    )?;
    let request = request(input)?;
    let live_owners = live
        .as_ref()
        .map(|live| sorted(live.inventory.owners.clone()))
        .filter(|owners| !owners.is_empty());
    if let Some(replayed) = replayed(input, &options, &request, live_owners.as_deref())? {
        return Ok(replayed);
    }
    let Some(backup) = newest(&options)? else {
        return Ok(refused(
            input,
            "No verified automatic backup exists in this home, so there is nothing to restore; nothing was changed.",
        ));
    };
    // A copy taken before any history was saved registers no owner and holds nothing.
    if backup.through.sequence() == 0 {
        return Ok(refused(
            input,
            "The newest automatic backup was taken before any history was saved, so it holds nothing to restore; nothing was changed. Keep using this home, or run se init to start a new store.",
        ));
    }
    let backup_owners = sorted(
        SqliteFactory::backup_owners(&options, &files, &backup).map_err(|e| store_error(&e))?,
    );
    if live_owners
        .as_ref()
        .is_some_and(|owners| *owners != backup_owners)
    {
        return Ok(refused(
            input,
            "The live store and the backup register different owners; nothing was changed.",
        ));
    }
    let owner = live_owners
        .as_ref()
        .unwrap_or(&backup_owners)
        .first()
        .cloned()
        .ok_or_else(|| SeError::invalid("restore owner", "a registered owner"))?;
    let mut planned = plan(input, &backup, live.as_ref());
    let blocking = live
        .as_ref()
        .map(|live| agents(&live.reader, &live.inventory, &owner))
        .unwrap_or_default();
    if !blocking.is_empty() {
        return Ok(RestoreResult {
            outcome: "refused".into(),
            blocking_agents: blocking,
            reason: Some("These agents still have live sessions; restoring now would discard their work. Let them finish, then run restore again.".into()),
            ..planned
        });
    }
    let running = matches!(execute::endpoint(&files)?, Read::Present { .. });
    if running && live.is_none() {
        // Without a readable store there is no census of live sessions, and the
        // ordinary stop needs one too.
        return Ok(RestoreResult {
            outcome: "refused".into(),
            reason: Some("A StateEngine host is running, but the live store cannot be read, so restore cannot check for live agent sessions. Stop it with `se down`; if that also fails, close the StateEngine host process. Then run restore again.".into()),
            ..planned
        });
    }
    if !input.yes {
        if running {
            planned.reason = Some("The idle StateEngine host will be stopped first.".into());
        }
        planned.next = Some(store_restore::confirm(input));
        return Ok(planned);
    }
    if running {
        stop_host(cx, input, diagnostic)?;
    }
    let target = match &live {
        Some(live) => live.inventory.store.id.clone(),
        None => backup.through.storage_parts().0.clone(),
    };
    drop(live);
    restore(&files, &options, backup, &request, target, &owner, planned)
}
/// The result this request already recorded, when it restored the store.
fn replayed(
    input: &StoreRestore,
    options: &StoreOptions,
    request: &RequestIdentity,
    live_owners: Option<&[HumanId]>,
) -> Result<Option<RestoreResult>> {
    if let Some(owner) = live_owners.and_then(|owners| owners.first()) {
        let admission = admission(owner);
        if let Read::Present { value } =
            SqliteFactory::recovery_receipt(options, request, &admission)
                .map_err(|e| store_error(&e))?
        {
            return Ok(Some(RestoreResult {
                receipt: Some(value.original_receipt),
                reason: Some(
                    "This request already restored the store; nothing was changed again.".into(),
                ),
                ..result(input, "restored")
            }));
        }
    }
    Ok(None)
}
fn plan(input: &StoreRestore, backup: &BackupGeneration, live: Option<&Live>) -> RestoreResult {
    let (backup_store, backup_incarnation, through) = backup.through.storage_parts();
    let events_lost = live.and_then(|live| live.head.as_ref()).and_then(|head| {
        let (store, incarnation, sequence) = head.storage_parts();
        (store == backup_store && incarnation == backup_incarnation)
            .then(|| sequence.saturating_sub(through))
    });
    RestoreResult {
        backup: Some(store_restore::RestoreBackup {
            id: uuid::Uuid::from_bytes(*backup.id.as_bytes()).to_string(),
            path: backup.path.display().to_string(),
            through_sequence: through,
            bytes: backup.bytes,
        }),
        events_lost,
        ..result(input, "planned")
    }
}
fn admission(owner: &HumanId) -> Admission {
    Admission {
        scope: Scope::Registry,
        actor: Actor::Human(owner.clone()),
        session: None,
        generation: 1,
    }
}
fn stop_host(
    cx: &Bootstrap,
    input: &StoreRestore,
    diagnostic: &mut dyn FnMut(&str) -> std::io::Result<()>,
) -> Result<()> {
    let down = RuntimeDown {
        idempotency_key: input.idempotency_key.clone(),
    };
    match execute::stop_for_uninstall(cx, down, diagnostic)? {
        AnyOutput::RuntimeDown(value)
            if value.value.complete && value.value.witness.state == WitnessState::Witnessed =>
        {
            Ok(())
        }
        _ => Err(scope::unreadable(
            "restore host shutdown",
            "the running host did not confirm it stopped; nothing was restored",
        )),
    }
}
fn restore(
    files: &Files,
    options: &StoreOptions,
    backup: BackupGeneration,
    request: &RequestIdentity,
    target: StoreId,
    owner: &HumanId,
    planned: RestoreResult,
) -> Result<RestoreResult> {
    let lease = DirectLease::acquire_restore(files, target.clone())
        .map_err(|e| store_error(&e))?
        .ok_or_else(|| {
            scope::unreadable(
                "restore exclusion",
                "a runtime, setup or writer still holds this home; nothing was restored. Run `se down`, then confirm the restore again",
            )
        })?;
    // Re-observe custody under the exclusive lock: an agent that started after
    // the plan still blocks.
    let generated_at = receipt::timestamp(execute::now_us()?)?;
    let mut unchecked = None;
    match setup::inspect(&options.state_directory, generated_at) {
        Ok(setup::Setup::Present(reader)) => {
            let blocking = agents(&reader, &owner::inventory(&reader, files)?, owner);
            if !blocking.is_empty() {
                return Ok(RestoreResult {
                    outcome: "refused".into(),
                    blocking_agents: blocking,
                    reason: Some(
                        "An agent session started before the restore; nothing was restored.".into(),
                    ),
                    ..planned
                });
            }
        }
        Ok(setup::Setup::Absent(_)) => (),
        Err(_) => {
            unchecked = Some("The live store could not be read, so live agent sessions could not be checked; no StateEngine host held this home.".to_string());
        }
    }
    let outcome =
        SqliteFactory::restore_backup(options, backup, request, target, &admission(owner), &lease)
            .map_err(|e| store_error(&e))?;
    let receipt = outcome.receipt.original_receipt;
    // An orderly host close takes a fresh backup, which would retire one of the
    // generations the owner may still want. The recovery fact is already
    // durable in the WAL, which the next open checkpoints.
    drop(outcome.host);
    let preserved = serde_json::from_str::<serde_json::Value>(&receipt)
        .ok()
        .and_then(|value| value.get("preserved")?.as_str().map(str::to_string));
    Ok(RestoreResult {
        outcome: "restored".into(),
        preserved,
        receipt: Some(receipt),
        reason: unchecked,
        ..planned
    })
}
