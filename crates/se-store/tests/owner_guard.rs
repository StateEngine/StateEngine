use se_store::*;
use se_types::{LifecycleId, Read};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;

// These are persisted schema fixtures, not native custody claims. The store
// preserves opaque reservation bytes; the native/core consumer must decode them.
fn recorded_reservation(
    f: &Fixture,
    unreadable: bool,
    custody: &[u8],
) -> Result<LifecycleId, Box<dyn std::error::Error>> {
    let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    db.execute_batch("PRAGMA foreign_keys=ON; BEGIN IMMEDIATE")?;
    let project = f.project.canonical_bytes()?.ok_or("project bytes")?;
    let actor = f.a.canonical_bytes()?.ok_or("agent bytes")?;
    let event = event()?.canonical_bytes()?.ok_or("event bytes")?;
    let process = LifecycleId::from_parts(1_700_000_000_000 + serial(), [71; 10])?;
    let process_bytes = process.canonical_bytes()?.ok_or("process bytes")?;
    let scope = [&[1u8][..], project.as_slice()].concat();
    db.execute("INSERT INTO operations(operation_id,scope_key,actor_id,recorded_incarnation,writer_mode,durability) VALUES(?,?,?,1,'direct','normal')", rusqlite::params![&event,scope,&actor])?;
    db.execute("INSERT INTO events(event_id,project_id,actor_id,origin_id,door,kind,schema_version,recorded_incarnation,entity_revision,writer_mode,durability,operation_id,occurred_at_us,recorded_at_us) VALUES(?,?,?,?,'host','process.registered',1,1,1,'direct','normal',?,1,1)",rusqlite::params![&event,&project,&actor,f.store.canonical_bytes()?.ok_or("store bytes")?,&event])?;
    let seq = db.last_insert_rowid();
    let (root, identity, state, cause) = if unreadable {
        (
            "unknown",
            "unreadable",
            "lost",
            "native identity unavailable",
        )
    } else {
        (
            "no-child-created",
            "absent",
            "reserved",
            "native launch has not created a child",
        )
    };
    db.execute("INSERT INTO process_data(event_seq,process_id,principal_id,root_identity,identity_state,identity_cause,custody_version,custody,containment,state) VALUES(?,?,?,?,?,?,1,?,'not-launched',?)",rusqlite::params![seq,&process_bytes,&actor,root,identity,cause,custody,state])?;
    db.execute("INSERT INTO processes(project_id,process_id,first_seq,revision,last_seq,state) VALUES(?,?,?,1,?,?)",rusqlite::params![&project,&process_bytes,seq,seq,state])?;
    db.execute("INSERT INTO operation_events(operation_id,ordinal,event_seq,newly_appended) VALUES(?,0,?,1)",rusqlite::params![&event,seq])?;
    db.execute_batch("COMMIT")?;
    Ok(process)
}

/// Protects: pre-admission owner guard — nonempty reservations retain scoped identities and opaque custody without partial budgets.
#[test]
fn complete_reservation_inventory_and_budget_refusals() -> Check {
    let f = Fixture::new()?;
    let (store, lease) = f.direct()?;
    let custody = b"persisted reservation fixture requiring the native decoder";
    let process = recorded_reservation(&f, false, custody)?;
    let inventory = store.owner_guard(&lease.files, budget(20, 32768, None)?)?;
    assert_eq!(inventory.owners, vec![f.owner.clone()]);
    assert_eq!(inventory.processes.len(), 1);
    let record = &inventory.processes[0];
    assert_eq!(record.project, f.project);
    assert_eq!(record.state, ProcessState::Reserved);
    assert_eq!(record.revision.value.get(), 1);
    assert_eq!(record.identity.record, process);
    assert_eq!(record.identity.principal, Actor::Agent(f.a.clone()));
    assert_eq!(record.identity.custody.record, custody);
    assert!(matches!(
        record.identity.instance,
        RecordedIdentity::Absent { .. }
    ));
    assert_eq!(
        store
            .owner_guard(&lease.files, budget(1, 32768, None)?)
            .err()
            .ok_or("partial inventory accepted")?
            .code,
        StoreErrorCode::ReadIncomplete
    );
    assert_eq!(
        store
            .owner_guard(&lease.files, budget(20, 64, None)?)
            .err()
            .ok_or("oversized inventory accepted")?
            .code,
        StoreErrorCode::ReadIncomplete
    );
    let mut immediate = budget(20, 32768, None)?;
    immediate.deadline = std::time::Duration::from_nanos(1);
    assert_eq!(
        store
            .owner_guard(&lease.files, immediate)
            .err()
            .ok_or("expired inventory accepted")?
            .code,
        StoreErrorCode::ReadIncomplete
    );
    let db = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    db.execute("UPDATE processes SET revision=2", [])?;
    assert_eq!(
        store
            .owner_guard(&lease.files, budget(20, 32768, None)?)
            .err()
            .ok_or("inconsistent process head accepted")?
            .code,
        StoreErrorCode::ProjectionInconsistent
    );
    drop(db);
    store.close()?;
    Ok(())
}

/// Protects: pre-admission owner guard — unreadable identity and absent custody refuse the complete inventory.
#[test]
fn unreadable_or_empty_process_facts_never_become_empty_inventory() -> Check {
    for (unreadable, custody) in [
        (true, b"opaque reservation".as_slice()),
        (false, b"".as_slice()),
    ] {
        let f = Fixture::new()?;
        let (store, lease) = f.direct()?;
        recorded_reservation(&f, unreadable, custody)?;
        assert_eq!(
            store
                .owner_guard(&lease.files, budget(20, 32768, None)?)
                .err()
                .ok_or("unreadable process omitted")?
                .code,
            StoreErrorCode::Unreadable
        );
        store.close()?;
    }
    Ok(())
}

/// Protects: pre-admission owner guard — even empty inventories charge their store/header metadata against the byte budget.
#[test]
fn empty_inventory_still_requires_its_metadata_budget() -> Check {
    let f = Fixture::new()?;
    let lease = Lease::acquire(&f.options.state_directory, LeaseMode::DirectClient, None)?;
    let store = SqliteFactory::create_direct(&f.options, &*lease, f.store.clone())?;
    assert_eq!(
        store
            .owner_guard(&lease.files, budget(20, 64, None)?)
            .err()
            .ok_or("empty inventory silently exceeded its byte budget")?
            .code,
        StoreErrorCode::ReadIncomplete
    );
    let full = store.owner_guard(&lease.files, budget(20, 32768, None)?)?;
    assert!(full.owners.is_empty());
    assert!(full.processes.is_empty());
    assert_eq!(full.store.id, f.store);
    assert!(matches!(
        SqliteFactory::open_reader(&f.options)?,
        Read::Present { .. }
    ));
    store.close()?;
    Ok(())
}
