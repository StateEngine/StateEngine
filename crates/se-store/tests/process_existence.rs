use se_store::*;
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/host_fixture.rs"]
mod host_fixture;
use host_fixture::{host, options, wait};

fn identity(f: &Fixture) -> Result<ProcessIdentityRecord, Box<dyn std::error::Error>> {
    Ok(ProcessIdentityRecord {
        record: se_types::LifecycleId::from_parts(1_700_000_000_000 + serial(), [84; 10])?,
        principal: Actor::Agent(f.a.clone()),
        session: None,
        root_identity: RootIdentityState::NoChildCreated,
        instance: RecordedIdentity::Absent {
            reason: "store reservation has created no native child".into(),
        },
        // Store-boundary bytes only. This test never decodes this fixture as
        // native custody, claims an OS exit or presents a native owner proof.
        custody: NativeCustody {
            format_version: 1,
            record: b"opaque store reservation fixture; no native authority".to_vec(),
        },
        containment: ContainmentFact::NotLaunched,
    })
}
fn inventory(
    reader: &SqliteReader,
    files: &dyn StateFiles,
) -> Result<OwnerGuardInventory, Box<dyn std::error::Error>> {
    Ok(reader.owner_guard(files, budget(20, 65536, None)?)?)
}

/// Protects: uninstall admission data — an initialized home with no process rows gives measured false alongside the unchanged empty unresolved inventory.
#[test]
fn initialized_home_without_process_records_is_measured_empty() -> Check {
    let f = Fixture::new()?;
    let (direct, lease) = f.direct()?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let view = inventory(&reader, &lease.files)?;
    assert!(!view.has_process_records);
    assert!(view.processes.is_empty());
    assert_eq!(view.owners, vec![f.owner.clone()]);
    drop(direct);
    Ok(())
}

/// Protects: home-wide process existence — a terminal reservation still exists even when the unresolved-native inventory correctly omits it, without claiming that a native child existed.
#[test]
fn exited_reservations_still_count_as_process_records() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let writer = host.start_writer(options(8)?, lease.clone())?;
    let client = writer.client();
    let id = identity(&f)?;
    let registered = wait(client.submit(f.batch(
        f.owner_project(),
        None,
        vec![EventBody::ProcessRegistered {
            identity: Box::new(id.clone()),
            initial: ProcessState::Reserved,
        }],
    )?)?)??;
    wait(client.submit(f.batch(
        f.owner_project(),
        None,
        vec![EventBody::ProcessTransition {
            process: id.record.clone(),
            identity: Box::new(id),
            expected: revision(1)?,
            from: ProcessState::Reserved,
            to: ProcessState::Exited,
            observation: registered.primary_event,
            outcome: "reservation ended without creating a child".into(),
            containment: ContainmentFact::NotLaunched,
        }],
    )?)?)??;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let view = inventory(&reader, &lease.files)?;
    assert!(
        view.has_process_records,
        "terminal rows became measured empty"
    );
    assert!(view.processes.is_empty());
    let drained = wait(writer.drain(std::time::Duration::from_secs(3)))??;
    drop(drained.host);
    Ok(())
}

/// Protects: release is not deletion — a released projection row remains present for uninstall even though the owner guard omits its native custody; this is a storage fixture, not a claimed native release action.
#[test]
fn released_projection_rows_still_count_as_process_records() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let writer = host.start_writer(options(8)?, lease.clone())?;
    wait(writer.client().submit(f.batch(
        f.owner_project(),
        None,
        vec![EventBody::ProcessRegistered {
            identity: Box::new(identity(&f)?),
            initial: ProcessState::Reserved,
        }],
    )?)?)??;
    // The wave-1 native release producer is deferred. Model only its retained
    // projection bit in this private DB, so the existence probe cannot regress
    // to the unresolved-owner filter; no runtime or OS fact is manufactured.
    let database = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    assert_eq!(
        database.execute("UPDATE processes SET ownership_released=1", [])?,
        1
    );
    drop(database);
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let view = inventory(&reader, &lease.files)?;
    assert!(
        view.has_process_records,
        "released row became measured empty"
    );
    assert!(view.processes.is_empty());
    let database = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    assert_eq!(
        database.execute(
            "UPDATE processes SET ownership_released=0,state='historical'",
            []
        )?,
        1
    );
    drop(database);
    let historical = inventory(&reader, &lease.files)?;
    assert!(
        historical.has_process_records,
        "historical projection row became measured empty"
    );
    assert!(historical.processes.is_empty());
    let drained = wait(writer.drain(std::time::Duration::from_secs(3)))??;
    drop(drained.host);
    Ok(())
}

/// Protects: unreadable is not none — missing schema or an insufficient protected-read budget refuses the entire inventory rather than returning false and permitting effects.
#[test]
fn unreadable_process_presence_and_incomplete_inventory_refuse() -> Check {
    let f = Fixture::new()?;
    let (direct, lease) = f.direct()?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    assert_eq!(
        reader
            .owner_guard(&lease.files, budget(20, 64, None)?)
            .err()
            .ok_or("partial inventory became process absence")?
            .code,
        StoreErrorCode::ReadIncomplete
    );
    drop(direct);
    let database = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    database.execute_batch("DROP TABLE processes")?;
    drop(database);
    let error = reader
        .owner_guard(&lease.files, budget(20, 65536, None)?)
        .err()
        .ok_or("unreadable process table became measured absence")?;
    assert!(matches!(
        error.code,
        StoreErrorCode::Unreadable | StoreErrorCode::ProjectionInconsistent
    ));
    Ok(())
}

/// Protects: uninstall's home-wide bound — a process registered only in another project is still present, independent of the caller's usual project.
#[test]
fn another_projects_process_is_in_the_home_wide_fact() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let writer = host.start_writer(options(8)?, lease.clone())?;
    let client = writer.client();
    let project = se_types::ProjectId::from_parts(1_700_000_000_000 + serial(), [85; 10])?;
    let principal = Actor::Agent(agent()?);
    let admission = f.admission(
        Scope::Project(project.clone()),
        Actor::Human(f.owner.clone()),
    );
    wait(client.submit(f.batch(
        admission.clone(),
        None,
        vec![EventBody::ProjectRegistered {
            project: project.clone(),
            name: "Other project".into(),
            roots: vec![],
            owner: f.owner.clone(),
            history_from: None,
            expected: Expected::Absent,
        }],
    )?)?)??;
    wait(client.submit(f.batch(
        admission.clone(),
        None,
        vec![EventBody::PrincipalRegistered {
            principal: principal.clone(),
            kind: PrincipalKind::Agent,
            owner: f.owner.clone(),
            created_by: None,
            name: "Other agent".into(),
            role: "builder".into(),
            expected: Expected::Absent,
        }],
    )?)?)??;
    let mut id = identity(&f)?;
    id.principal = principal;
    wait(client.submit(f.batch(
        admission,
        None,
        vec![EventBody::ProcessRegistered {
            identity: Box::new(id),
            initial: ProcessState::Reserved,
        }],
    )?)?)??;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let view = inventory(&reader, &lease.files)?;
    assert!(view.has_process_records);
    assert_eq!(view.processes.len(), 1);
    assert_eq!(view.processes[0].project, project);
    let drained = wait(writer.drain(std::time::Duration::from_secs(3)))??;
    drop(drained.host);
    Ok(())
}
