#![cfg(any(target_os = "linux", windows))]
use se_store::*;
use se_types::LifecycleId;
use std::time::Duration;
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/host_fixture.rs"]
mod native_host;
use native_host::*;
#[path = "support/capture_fixture.rs"]
#[allow(
    dead_code,
    reason = "Process tests share only typed session preparation."
)]
mod capture_fixture;

fn identity(
    f: &Fixture,
    published: bool,
) -> Result<ProcessIdentityRecord, Box<dyn std::error::Error>> {
    let n = serial();
    Ok(ProcessIdentityRecord {
        record: LifecycleId::from_parts(1_700_000_000_000 + n, [n as u8; 10])?,
        principal: Actor::Agent(f.a.clone()),
        session: None,
        root_identity: if published {
            RootIdentityState::Identified
        } else {
            RootIdentityState::NoChildCreated
        },
        instance: if published {
            RecordedIdentity::Present(epoch()?.owner)
        } else {
            RecordedIdentity::Absent {
                reason: "reservation has no child".into(),
            }
        },
        // Opaque store-boundary fixture, never a native custody/stop authority claim.
        custody: NativeCustody {
            format_version: 1,
            record: b"store process boundary fixture; native decoding is separate".to_vec(),
        },
        containment: ContainmentFact::NotLaunched,
    })
}
fn registration(i: &ProcessIdentityRecord, initial: ProcessState) -> EventBody<InputText> {
    EventBody::ProcessRegistered {
        identity: Box::new(i.clone()),
        initial,
    }
}
fn transition(
    i: &ProcessIdentityRecord,
    rev: u64,
    from: ProcessState,
    to: ProcessState,
    observation: se_types::EventId,
) -> Result<EventBody<InputText>, Box<dyn std::error::Error>> {
    Ok(EventBody::ProcessTransition {
        process: i.record.clone(),
        identity: Box::new(i.clone()),
        expected: revision(rev)?,
        from,
        to,
        observation,
        outcome: "outside observation retained".into(),
        containment: i.containment.clone(),
    })
}
fn head(f: &Fixture, id: LifecycleId) -> Result<ProjectionRecord, Box<dyn std::error::Error>> {
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut snapshot = reader.snapshot(f.scoped(Visibility::Owner))?;
    present(snapshot.process(id)?)
}

/// Protects: 20 process producer — host registration feeds the same complete typed identity into point, original and protected inventory reads.
#[test]
fn typed_process_registration_and_stop_transitions_roundtrip() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let owner = host.start_writer(options(256)?, lease.clone())?;
    let client = owner.client();
    let mut i = identity(&f, false)?;
    let first = wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!("fixture-store_process-85-{}", serial()))?),
        vec![registration(&i, ProcessState::Reserved)],
    )?)?)??;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let inventory = reader.owner_guard(&lease.files, budget(20, 32768, None)?)?;
    assert_eq!(inventory.processes.len(), 1);
    assert_eq!(inventory.processes[0].identity.record, i.record);
    assert_eq!(
        inventory.processes[0].identity.custody.record,
        i.custody.record
    );
    i.root_identity = RootIdentityState::Unpublished;
    for (rev, from, to) in [
        (1, ProcessState::Reserved, ProcessState::Starting),
        (2, ProcessState::Starting, ProcessState::StopRequested),
        (3, ProcessState::StopRequested, ProcessState::StopUnproved),
        (4, ProcessState::StopUnproved, ProcessState::StopRequested),
        (5, ProcessState::StopRequested, ProcessState::Exited),
    ] {
        wait(client.submit(f.batch(
            f.owner_project(),
            Some(request(&format!("fixture-store_process-106-{}", serial()))?),
            vec![transition(&i, rev, from, to, first.primary_event.clone())?],
        )?)?)??;
        let current = head(&f, i.record.clone())?;
        assert_eq!(current.revision.value.get(), rev + 1);
        let EventBody::ProcessTransition {
            identity,
            to: actual,
            ..
        } = current.current.body
        else {
            return Err("process head lost transition kind".into());
        };
        assert_eq!(actual, to);
        assert_eq!(identity.record, i.record);
        assert_eq!(identity.custody.record, i.custody.record);
        assert!(matches!(
            current.original.ok_or("process lost original")?.body,
            EventBody::ProcessRegistered {
                initial: ProcessState::Reserved,
                ..
            }
        ));
    }
    assert!(
        reader
            .owner_guard(&lease.files, budget(20, 32768, None)?)?
            .processes
            .is_empty()
    );
    drop(wait(owner.drain(Duration::from_secs(2)))??);
    Ok(())
}

/// Protects: 20 process producer — stale revision, wrong source state, terminal revival and native/principal drift never advance the process head.
#[test]
fn process_transition_cas_identity_and_atomic_rollback() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let owner = host.start_writer(options(256)?, lease.clone())?;
    let client = owner.client();
    let sid = capture_fixture::session()?;
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!("fixture-store_process-150-{}", serial()))?),
        vec![capture_fixture::prepared(&f, &sid, &f.a)],
    )?)?)??;
    let i = identity(&f, true)?;
    let first = wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!("fixture-store_process-156-{}", serial()))?),
        vec![registration(&i, ProcessState::Running)],
    )?)?)??;
    for (rev, from, to) in [
        (99, ProcessState::Running, ProcessState::StopRequested),
        (1, ProcessState::Starting, ProcessState::StopRequested),
        (1, ProcessState::Running, ProcessState::Starting),
    ] {
        assert!(
            wait(client.submit(f.batch(
                f.owner_project(),
                Some(request(&format!(
                    "judge-nested-store_process-167-{}",
                    serial()
                ))?),
                vec![transition(&i, rev, from, to, first.primary_event.clone())?]
            )?)?)?
            .is_err()
        );
        assert_eq!(head(&f, i.record.clone())?.revision.value.get(), 1);
    }
    let mut changed = i.clone();
    changed.principal = Actor::Agent(f.b.clone());
    let mut birth = i.clone();
    let RecordedIdentity::Present(instance) = &i.instance else {
        return Err("native instance absent".into());
    };
    let mut fields = instance.fields().clone();
    fields.argv_sha256 = se_types::Sha256::from_bytes([91; 32]);
    birth.instance =
        RecordedIdentity::Present(se_types::ProcessInstance::from_observation(fields)?);
    let mut session_drift = i.clone();
    session_drift.session = Some(sid);
    for drift in [changed, birth, session_drift] {
        assert_eq!(
            wait(client.submit(f.batch(
                f.owner_project(),
                Some(request(&format!(
                    "judge-nested-store_process-190-{}",
                    serial()
                ))?),
                vec![transition(
                    &drift,
                    1,
                    ProcessState::Running,
                    ProcessState::StopRequested,
                    first.primary_event.clone()
                )?]
            )?)?)?
            .err()
            .ok_or("process identity drift accepted")?
            .code,
            StoreErrorCode::SourceChanged
        );
    }
    let invalid = transition(
        &i,
        99,
        ProcessState::StopRequested,
        ProcessState::StopUnproved,
        first.primary_event.clone(),
    )?;
    assert!(
        wait(client.submit(f.batch(
            f.owner_project(),
            Some(request(&format!(
                "judge-nested-store_process-215-{}",
                serial()
            ))?),
            vec![
                transition(
                    &i,
                    1,
                    ProcessState::Running,
                    ProcessState::StopRequested,
                    first.primary_event.clone()
                )?,
                invalid
            ]
        )?)?)?
        .is_err()
    );
    assert_eq!(head(&f, i.record.clone())?.revision.value.get(), 1);
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!("fixture-store_process-232-{}", serial()))?),
        vec![transition(
            &i,
            1,
            ProcessState::Running,
            ProcessState::Exited,
            first.primary_event.clone(),
        )?],
    )?)?)??;
    assert!(
        wait(client.submit(f.batch(
            f.owner_project(),
            Some(request(&format!(
                "judge-nested-store_process-244-{}",
                serial()
            ))?),
            vec![transition(
                &i,
                2,
                ProcessState::Exited,
                ProcessState::Running,
                first.primary_event.clone()
            )?]
        )?)?)?
        .is_err()
    );
    drop(wait(owner.drain(Duration::from_secs(2)))??);
    Ok(())
}

/// Protects: 20 § process identity — a published native root survives loss and cannot be discarded as an unreadable observation.
#[test]
fn loss_never_discards_an_already_published_native_birth_identity() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let owner = host.start_writer(options(256)?, lease.clone())?;
    let client = owner.client();
    let i = identity(&f, true)?;
    let first = wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!("fixture-store_process-269-{}", serial()))?),
        vec![registration(&i, ProcessState::Running)],
    )?)?)??;
    let mut lost = i.clone();
    lost.root_identity = RootIdentityState::Unknown;
    lost.instance = RecordedIdentity::Unreadable {
        cause: "outside probe is temporarily unreadable".into(),
    };
    let result = wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!("fixture-store_process-279-{}", serial()))?),
        vec![transition(
            &lost,
            1,
            ProcessState::Running,
            ProcessState::Lost,
            first.primary_event.clone(),
        )?],
    )?)?)?;
    let retained_revision = head(&f, i.record.clone())?.revision.value.get();
    drop(wait(owner.drain(Duration::from_secs(2)))??);
    let error = result
        .err()
        .ok_or("loss discarded a previously published native birth identity")?;
    assert!(matches!(
        error.code,
        StoreErrorCode::SourceChanged | StoreErrorCode::InvalidTransition
    ));
    assert_eq!(retained_revision, 1);
    Ok(())
}

/// Protects: 20 process producer — direct-client writes and mismatched principal/session registration refuse before any durable process appears.
#[test]
fn direct_registration_and_foreign_session_refuse() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let mut i = identity(&f, false)?;
    assert!(
        d.append(
            f.batch(
                f.owner_project(),
                Some(request(&format!(
                    "judge-nested-store_process-311-{}",
                    serial()
                ))?),
                vec![registration(&i, ProcessState::Reserved)]
            )?,
            &*lease
        )
        .is_err()
    );
    d.close()?;
    drop(lease);
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let owner = host.start_writer(options(256)?, lease.clone())?;
    let client = owner.client();
    let session = capture_fixture::session()?;
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!("fixture-store_process-327-{}", serial()))?),
        vec![capture_fixture::prepared(&f, &session, &f.b)],
    )?)?)??;
    i = identity(&f, false)?;
    i.session = Some(session);
    assert_eq!(
        wait(client.submit(f.batch(
            f.owner_project(),
            Some(request(&format!(
                "judge-nested-store_process-335-{}",
                serial()
            ))?),
            vec![registration(&i, ProcessState::Reserved)]
        )?)?)?
        .err()
        .ok_or("foreign session accepted")?
        .code,
        StoreErrorCode::ScopeMismatch
    );
    assert!(
        present(SqliteFactory::open_reader(&f.options)?)?
            .owner_guard(&lease.files, budget(20, 32768, None)?)?
            .processes
            .is_empty()
    );
    drop(wait(owner.drain(Duration::from_secs(2)))??);
    Ok(())
}

/// Protects: 20 process identity — preserving the saved native identity permits Lost and exact-identity recovery instead of forbidding loss altogether.
#[test]
fn saved_native_identity_survives_loss_and_recovery() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let owner = host.start_writer(options(256)?, lease.clone())?;
    let client = owner.client();
    let i = identity(&f, true)?;
    let first = wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!("fixture-store_process-363-{}", serial()))?),
        vec![registration(&i, ProcessState::Running)],
    )?)?)??;
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!("fixture-store_process-368-{}", serial()))?),
        vec![transition(
            &i,
            1,
            ProcessState::Running,
            ProcessState::Lost,
            first.primary_event.clone(),
        )?],
    )?)?)??;
    {
        let reader = present(SqliteFactory::open_reader(&f.options)?)?;
        let inventory = reader.owner_guard(&lease.files, budget(20, 32768, None)?)?;
        assert_eq!(inventory.processes.len(), 1);
        let saved = &inventory.processes[0];
        assert_eq!(saved.state, ProcessState::Lost);
        assert_eq!(saved.revision.value.get(), 2);
        let (RecordedIdentity::Present(saved), RecordedIdentity::Present(original)) =
            (&saved.identity.instance, &i.instance)
        else {
            return Err("loss discarded the saved native identity".into());
        };
        assert_eq!(saved, original);
    }
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!("fixture-store_process-393-{}", serial()))?),
        vec![transition(
            &i,
            2,
            ProcessState::Lost,
            ProcessState::Running,
            first.primary_event.clone(),
        )?],
    )?)?)??;
    let current = head(&f, i.record.clone())?;
    assert_eq!(current.revision.value.get(), 3);
    let EventBody::ProcessTransition {
        identity,
        from: ProcessState::Lost,
        to: ProcessState::Running,
        ..
    } = current.current.body
    else {
        return Err("recovery did not preserve its source/target state".into());
    };
    let (RecordedIdentity::Present(saved), RecordedIdentity::Present(original)) =
        (&identity.instance, &i.instance)
    else {
        return Err("recovery discarded the saved native identity".into());
    };
    assert_eq!(saved, original);
    drop(wait(owner.drain(Duration::from_secs(2)))??);
    Ok(())
}

/// A console's second C2 may change only argv, once, on the same pre-exec root.
#[test]
fn console_argv_handoff_preserves_native_custody_and_cannot_repeat() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let owner = host.start_writer(options(256)?, lease)?;
    let client = owner.client();
    let mut i = identity(&f, false)?;
    let mut last = wait(client.submit(f.batch(
        f.owner_project(),
        None,
        vec![registration(&i, ProcessState::Reserved)],
    )?)?)??
    .primary_event;
    i.root_identity = RootIdentityState::Unpublished;
    let mut scope = transition(&i, 1, ProcessState::Reserved, ProcessState::Starting, last)?;
    if let EventBody::ProcessTransition { outcome, .. } = &mut scope {
        *outcome = "scope-prepared".into();
    }
    last = wait(client.submit(f.batch(f.owner_project(), None, vec![scope])?)?)??.primary_event;
    i.root_identity = RootIdentityState::Identified;
    i.instance = RecordedIdentity::Present(epoch()?.owner);
    let mut root = transition(&i, 2, ProcessState::Starting, ProcessState::Starting, last)?;
    if let EventBody::ProcessTransition { outcome, .. } = &mut root {
        *outcome = "root-prepared".into();
    }
    last = wait(client.submit(f.batch(f.owner_project(), None, vec![root])?)?)??.primary_event;
    let RecordedIdentity::Present(original) = &i.instance else {
        return Err("missing root".into());
    };
    let mut fields = original.fields().clone();
    fields.argv_sha256 = se_types::Sha256::from_bytes([42; 32]);
    let mut console = i.clone();
    console.instance =
        RecordedIdentity::Present(se_types::ProcessInstance::from_observation(fields.clone())?);
    let mut changed_pid = console.clone();
    fields.pid = std::num::NonZeroU32::new(fields.pid.get() + 1).ok_or("pid overflow")?;
    changed_pid.instance =
        RecordedIdentity::Present(se_types::ProcessInstance::from_observation(fields)?);
    let mut changed_custody = console.clone();
    changed_custody.custody.record.push(0);
    for (drift, phase) in [
        (changed_pid, "console-prepared"),
        (changed_custody, "console-prepared"),
        (console.clone(), "other-phase"),
    ] {
        let mut event = transition(
            &drift,
            3,
            ProcessState::Starting,
            ProcessState::Starting,
            last.clone(),
        )?;
        if let EventBody::ProcessTransition { outcome, .. } = &mut event {
            *outcome = phase.into();
        }
        assert!(wait(client.submit(f.batch(f.owner_project(), None, vec![event])?)?)?.is_err());
        assert_eq!(head(&f, i.record.clone())?.revision.value.get(), 3);
    }
    let mut event = transition(
        &console,
        3,
        ProcessState::Starting,
        ProcessState::Starting,
        last,
    )?;
    if let EventBody::ProcessTransition { outcome, .. } = &mut event {
        *outcome = "console-prepared".into();
    }
    last = wait(client.submit(f.batch(f.owner_project(), None, vec![event])?)?)??.primary_event;
    let mut repeat = transition(
        &i,
        4,
        ProcessState::Starting,
        ProcessState::Starting,
        last.clone(),
    )?;
    if let EventBody::ProcessTransition { outcome, .. } = &mut repeat {
        *outcome = "console-prepared".into();
    }
    assert!(wait(client.submit(f.batch(f.owner_project(), None, vec![repeat])?)?)?.is_err());
    wait(client.submit(f.batch(
        f.owner_project(),
        None,
        vec![transition(
            &console,
            4,
            ProcessState::Starting,
            ProcessState::Running,
            last,
        )?],
    )?)?)??;
    assert_eq!(head(&f, i.record.clone())?.revision.value.get(), 5);
    drop(wait(owner.drain(Duration::from_secs(2)))??);
    Ok(())
}
