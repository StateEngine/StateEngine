use se_store::*;
use se_types::Read;
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[allow(
    dead_code,
    reason = "Only the shared credential event constructors are needed here."
)]
#[path = "support/capture_fixture.rs"]
mod capture_fixture;
use capture_fixture::*;
#[allow(
    dead_code,
    reason = "Only the shared native ownership fixture is needed here."
)]
#[path = "support/host_fixture.rs"]
mod host_fixture;

/// Protects: private lookups and the admitted snapshot use one actual pin and
/// one shared reservation, and a later phase sees intervening committed data.
#[test]
fn one_pin_transfers_to_snapshot_without_another_slot() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let phase = reader.read_phase()?;
    let other = reader.clone().read_phase()?;
    assert!(matches!(phase.runtime_owner()?, Read::Absent { .. }));
    assert!(matches!(phase.credential([19; 32])?, Read::Absent { .. }));
    assert_eq!(
        phase
            .owner_guard(&lease.files, budget(20, 32768, None)?)?
            .owners,
        vec![f.owner.clone()]
    );
    assert_eq!(
        reader.read_phase().err().ok_or("third pin admitted")?.code,
        StoreErrorCode::Backpressure
    );
    // A real concurrent commit proves that consuming the phase does not open a
    // new transaction. The host closes this pin before its own commit boundary.
    writer.append(
        f.working("after the pin", Expected::Absent, "phase-state")?,
        &*lease,
    )?;
    let mut snapshot = phase.into_snapshot(f.self_scope(&f.a))?;
    assert!(matches!(
        snapshot.working_state(f.a.clone())?,
        Read::Absent { .. }
    ));
    assert_eq!(
        reader
            .read_phase()
            .err()
            .ok_or("snapshot lost its slot")?
            .code,
        StoreErrorCode::Backpressure
    );
    snapshot.close()?;
    let fresh = reader.read_phase()?;
    let mut snapshot = fresh.into_snapshot(f.self_scope(&f.a))?;
    let value = present(snapshot.working_state(f.a.clone())?)?;
    assert!(matches!(value.current.body, EventBody::WorkingStateSet {
        text: StoredText::Present(ref text), ..
    } if text == "after the pin"));
    snapshot.close()?;
    other.close()?;
    writer.close()?;
    Ok(())
}

/// Protects: credential authority is read again after a phase ends; neither
/// prepared nor active authority survives a later committed revocation.
#[test]
fn new_phase_observes_credential_activation_and_revocation() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let id = session()?;
    let credential = record()?;
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros(),
    )?;
    writer.append(
        f.batch(
            f.owner_project(),
            Some(request(&format!("fixture-read_phase-88-{}", serial()))?),
            vec![
                prepared(&f, &id, &f.a),
                EventBody::CredentialIssued {
                    credential,
                    session: id.clone(),
                    purpose: "session".into(),
                    secret_sha256: [17; 32],
                    expires_at_us: now + 300_000_000,
                    activation_deadline_us: now + 60_000_000,
                    expected: Expected::Absent,
                },
            ],
        )?,
        &*lease,
    )?;
    let phase = reader.read_phase()?;
    assert_eq!(
        present(phase.credential([17; 32])?)?.state,
        CredentialState::Prepared
    );
    phase.close()?;
    writer.append(
        f.batch(
            f.owner_project(),
            Some(request(&format!("fixture-read_phase-113-{}", serial()))?),
            vec![
                activated(&id)?,
                EventBody::CredentialActivated {
                    credential,
                    session: id.clone(),
                    expected: revision(1)?,
                    first_request: record()?,
                },
            ],
        )?,
        &*lease,
    )?;
    let phase = reader.read_phase()?;
    assert_eq!(
        present(phase.credential([17; 32])?)?.state,
        CredentialState::Active
    );
    phase.close()?;
    writer.append(
        f.batch(
            f.owner_project(),
            Some(request(&format!("fixture-read_phase-135-{}", serial()))?),
            vec![EventBody::CredentialRevoked {
                credential,
                expected: revision(2)?,
                reason: InputText::Inline("revoked".into()),
            }],
        )?,
        &*lease,
    )?;
    let phase = reader.clone().read_phase()?;
    assert_eq!(
        present(phase.credential([17; 32])?)?.state,
        CredentialState::Revoked
    );
    phase.close()?;
    assert_eq!(
        present(reader.credential([17; 32])?)?.state,
        CredentialState::Revoked
    );
    writer.close()?;
    Ok(())
}

/// Protects: failed budget reads and abandoned phases cannot strand a
/// reservation or prevent the next real read transaction from starting.
#[test]
fn failed_queries_and_drop_return_the_shared_budget() -> Check {
    let f = Fixture::new()?;
    let (writer, lease) = f.direct()?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    for _ in 0..4 {
        let phase = reader.read_phase()?;
        assert!(
            phase
                .owner_guard(&lease.files, budget(1, 1024, None)?)
                .is_err()
        );
        drop(phase);
        let first = reader.read_phase()?;
        let second = reader.clone().read_phase()?;
        assert_eq!(
            reader
                .snapshot(f.scoped(Visibility::Owner))
                .err()
                .ok_or("third snapshot admitted")?
                .code,
            StoreErrorCode::Backpressure
        );
        first.close()?;
        second.close()?;
    }
    writer.close()?;
    Ok(())
}

/// Protects: a fresh phase re-reads the actual committed owner generation.
#[test]
fn owner_generation_is_not_reused_across_phases() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host_fixture::host(&f)?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let phase = reader.read_phase()?;
    assert_eq!(present(phase.runtime_owner()?)?.generation.get(), 1);
    phase.close()?;
    drop(host);
    lease.identity.lock().map_err(|_| "lease mutex")?.generation = 2;
    let mut host = present(SqliteFactory::open_host(&f.options, &*lease)?)?;
    let mut epoch = host_fixture::epoch()?;
    epoch.generation = se_types::HostGeneration::new(2)?;
    let mut admission = f.admission(Scope::Registry, Actor::Human(f.owner.clone()));
    admission.generation = 2;
    host.record_runtime_ownership(
        f.batch(
            admission,
            Some(request("next-runtime-owner")?),
            vec![EventBody::RuntimeOwnerEstablished {
                epoch,
                generation: se_types::Generation::new(2)?,
                expected_owner_generation: Some(se_types::Generation::new(1)?),
                expected: revision(1)?,
                witnesses: vec![],
                recovered: None,
            }],
        )?,
        &*lease,
    )?;
    let phase = reader.clone().read_phase()?;
    let current = present(phase.runtime_owner()?)?;
    assert_eq!(current.generation.get(), 2);
    assert_eq!(current.revision.value.get(), 2);
    phase.close()?;
    assert_eq!(present(reader.runtime_owner()?)?.generation.get(), 2);
    Ok(())
}
