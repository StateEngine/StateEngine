//! Independent wave-2 store judges. These persist typed store facts; they do
//! not claim native launch custody, provider execution or host authentication.
#![cfg(any(target_os = "linux", windows))]
use se_store::*;
use se_types::{AgentId, LifecycleId, NativePath};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/host_fixture.rs"]
mod native_host;
use native_host::*;
#[path = "support/capture_fixture.rs"]
#[allow(dead_code, reason = "only typed session preparation is shared")]
mod capture;

#[path = "support/wave2_control_fixture.rs"]
#[allow(
    dead_code,
    reason = "checkpoint and creator judges share typed store fixtures"
)]
mod control_fixture;
use control_fixture::*;
/// Protects: one root checkpoint and one exec image change preserve every other native identity and exact revision.
#[test]
fn checkpoint_and_exec_preserve_birth_and_revision() -> Check {
    let f = Fixture::new()?;
    let (host, lease) = host(&f)?;
    let writer = host.start_writer(options(256)?, lease)?;
    let client = writer.client();
    let mut i = identity(&f.a)?;
    let first = wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!(
            "fixture-wave2_checkpoint_independent-32-{}",
            serial()
        ))?),
        vec![registration(&i, ProcessState::Starting)],
    )?)?)??;
    checkpoint_requires_a_published_root(&f, &client, &i, &first)?;
    let mut fields = epoch()?.owner.fields().clone();
    fields.executable = NativePath::from_local(f.home.join("authenticated-helper"))?;
    i.root_identity = RootIdentityState::Identified;
    i.instance =
        RecordedIdentity::Present(se_types::ProcessInstance::from_observation(fields.clone())?);
    only_one_checkpoint_per_root(&f, &client, &i, &first)?;
    fields.executable = NativePath::from_local(f.home.join("verified-vendor"))?;
    let mut premature = i.clone();
    premature.instance =
        RecordedIdentity::Present(se_types::ProcessInstance::from_observation(fields.clone())?);
    exec_refuses_edge_principal_and_session_drift(&f, &client, &i, &premature, &first)?;
    exec_refuses_native_identity_drift(&f, &client, &i, &fields, &first)?;
    exec_commits_once_then_pins_the_image(&f, &client, i, fields, first)?;
    drop(wait_drained(writer.drain(DRAIN_DEADLINE))??);
    Ok(())
}

fn checkpoint_requires_a_published_root(
    f: &Fixture,
    client: &SqliteClient,
    i: &ProcessIdentityRecord,
    first: &CommitReceipt,
) -> Check {
    assert!(
        wait(client.submit(f.batch(
            f.owner_project(),
            Some(request(&format!(
                "judge-nested-wave2_checkpoint_independent-41-{}",
                serial()
            ))?),
            vec![transition(
                i,
                1,
                ProcessState::Starting,
                ProcessState::Starting,
                first.primary_event.clone()
            )?]
        )?)?)?
        .is_err(),
        "no-op checkpoint admitted"
    );
    let mut no_child = identity(&f.a)?;
    no_child.root_identity = RootIdentityState::NoChildCreated;
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!(
            "fixture-wave2_checkpoint_independent-54-{}",
            serial()
        ))?),
        vec![registration(&no_child, ProcessState::Starting)],
    )?)?)??;
    let mut invalid_checkpoint = no_child.clone();
    invalid_checkpoint.root_identity = RootIdentityState::Identified;
    invalid_checkpoint.instance = RecordedIdentity::Present(epoch()?.owner);
    assert!(
        wait(client.submit(f.batch(
            f.owner_project(),
            Some(request(&format!(
                "judge-nested-wave2_checkpoint_independent-69-{}",
                serial()
            ))?),
            vec![transition(
                &invalid_checkpoint,
                1,
                ProcessState::Starting,
                ProcessState::Starting,
                first.primary_event.clone()
            )?]
        )?)?)?
        .is_err(),
        "NoChildCreated predecessor admitted as checkpoint"
    );
    assert_eq!(head(f, no_child.record)?.revision.value.get(), 1);
    Ok(())
}

fn only_one_checkpoint_per_root(
    f: &Fixture,
    client: &SqliteClient,
    i: &ProcessIdentityRecord,
    first: &CommitReceipt,
) -> Check {
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!(
            "fixture-wave2_checkpoint_independent-83-{}",
            serial()
        ))?),
        vec![transition(
            i,
            1,
            ProcessState::Starting,
            ProcessState::Starting,
            first.primary_event.clone(),
        )?],
    )?)?)??;
    assert_eq!(head(f, i.record.clone())?.revision.value.get(), 2);
    assert!(
        wait(client.submit(f.batch(
            f.owner_project(),
            Some(request(&format!(
                "judge-nested-wave2_checkpoint_independent-105-{}",
                serial()
            ))?),
            vec![transition(
                i,
                2,
                ProcessState::Starting,
                ProcessState::Starting,
                first.primary_event.clone()
            )?]
        )?)?)?
        .is_err(),
        "second checkpoint admitted"
    );
    Ok(())
}

fn exec_refuses_edge_principal_and_session_drift(
    f: &Fixture,
    client: &SqliteClient,
    i: &ProcessIdentityRecord,
    premature: &ProcessIdentityRecord,
    first: &CommitReceipt,
) -> Check {
    assert_eq!(
        wait(client.submit(f.batch(
            f.owner_project(),
            Some(request(&format!(
                "judge-nested-wave2_checkpoint_independent-124-{}",
                serial()
            ))?),
            vec![transition(
                premature,
                2,
                ProcessState::Starting,
                ProcessState::StopRequested,
                first.primary_event.clone()
            )?]
        )?)?)?
        .err()
        .ok_or("image changed outside exec edge")?
        .code,
        StoreErrorCode::SourceChanged
    );
    let target_session = capture::session()?;
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!(
            "fixture-wave2_checkpoint_independent-132-{}",
            serial()
        ))?),
        vec![capture::prepared(f, &target_session, &f.a)],
    )?)?)??;
    for kind in ["principal", "session"] {
        let mut drift = premature.clone();
        if kind == "principal" {
            drift.principal = Actor::Agent(f.b.clone());
        } else {
            drift.session = Some(target_session.clone());
        }
        assert_eq!(
            wait(client.submit(f.batch(
                f.owner_project(),
                Some(request(&format!(
                    "judge-nested-wave2_checkpoint_independent-157-{}",
                    serial()
                ))?),
                vec![transition(
                    &drift,
                    2,
                    ProcessState::Starting,
                    ProcessState::Running,
                    first.primary_event.clone()
                )?]
            )?)?)?
            .err()
            .ok_or("exec changed principal/session")?
            .code,
            StoreErrorCode::SourceChanged
        );
        assert_eq!(head(f, i.record.clone())?.revision.value.get(), 2);
    }
    Ok(())
}

fn exec_refuses_native_identity_drift(
    f: &Fixture,
    client: &SqliteClient,
    i: &ProcessIdentityRecord,
    fields: &se_types::ProcessFields,
    first: &CommitReceipt,
) -> Check {
    for field in ["machine", "boot", "pid", "birth", "argv"] {
        let mut changed = fields.clone();
        match field {
            "machine" => changed.machine = se_types::MachineId::new("different-machine")?,
            "boot" => changed.boot = se_types::BootId::new("different-boot")?,
            "pid" => changed.pid = std::num::NonZeroU32::new(changed.pid.get() + 1).ok_or("pid")?,
            "birth" => match &mut changed.started {
                se_types::StartIdentity::Linux { start_ticks } => *start_ticks += 1,
                se_types::StartIdentity::Windows { creation_filetime } => {
                    *creation_filetime =
                        std::num::NonZeroU64::new(creation_filetime.get() + 1).ok_or("birth")?
                }
                se_types::StartIdentity::Macos { start_seconds, .. } => *start_seconds += 1,
            },
            "argv" => changed.argv_sha256 = se_types::Sha256::from_bytes([91; 32]),
            _ => return Err("unknown identity matrix field".into()),
        }
        let mut drift = i.clone();
        drift.instance =
            RecordedIdentity::Present(se_types::ProcessInstance::from_observation(changed)?);
        let refused = wait(client.submit(f.batch(
            f.owner_project(),
            Some(request(&format!(
                "fixture-wave2_checkpoint_independent-183-{}",
                serial()
            ))?),
            vec![transition(
                &drift,
                2,
                ProcessState::Starting,
                ProcessState::Running,
                first.primary_event.clone(),
            )?],
        )?)?)?;
        assert_eq!(
            refused
                .err()
                .ok_or(format!("exec accepted {field} drift"))?
                .code,
            StoreErrorCode::SourceChanged
        );
        assert_eq!(
            head(f, i.record.clone())?.revision.value.get(),
            2,
            "refused drift advanced revision"
        );
    }
    Ok(())
}

fn exec_commits_once_then_pins_the_image(
    f: &Fixture,
    client: &SqliteClient,
    mut i: ProcessIdentityRecord,
    mut fields: se_types::ProcessFields,
    first: CommitReceipt,
) -> Check {
    i.instance =
        RecordedIdentity::Present(se_types::ProcessInstance::from_observation(fields.clone())?);
    assert!(
        wait(client.submit(f.batch(
            f.owner_project(),
            Some(request(&format!(
                "judge-nested-wave2_checkpoint_independent-225-{}",
                serial()
            ))?),
            vec![transition(
                &i,
                1,
                ProcessState::Starting,
                ProcessState::Running,
                first.primary_event.clone()
            )?]
        )?)?)?
        .is_err(),
        "stale checkpoint revision admitted"
    );
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!(
            "fixture-wave2_checkpoint_independent-224-{}",
            serial()
        ))?),
        vec![transition(
            &i,
            2,
            ProcessState::Starting,
            ProcessState::Running,
            first.primary_event.clone(),
        )?],
    )?)?)??;
    let current = head(f, i.record.clone())?;
    assert_eq!(current.revision.value.get(), 3);
    assert!(
        matches!(current.current.body, EventBody::ProcessTransition { identity, to: ProcessState::Running, .. } if matches!((&identity.instance, &i.instance), (RecordedIdentity::Present(a), RecordedIdentity::Present(b)) if a == b))
    );
    let mut drift = i.clone();
    fields.executable = NativePath::from_local(f.home.join("third-image"))?;
    drift.instance =
        RecordedIdentity::Present(se_types::ProcessInstance::from_observation(fields)?);
    assert_eq!(
        wait(client.submit(f.batch(
            f.owner_project(),
            Some(request(&format!(
                "judge-nested-wave2_checkpoint_independent-263-{}",
                serial()
            ))?),
            vec![transition(
                &drift,
                3,
                ProcessState::Running,
                ProcessState::StopRequested,
                first.primary_event.clone()
            )?]
        )?)?)?
        .err()
        .ok_or("post-exec image drift admitted")?
        .code,
        StoreErrorCode::SourceChanged
    );
    wait(client.submit(f.batch(
        f.owner_project(),
        Some(request(&format!(
            "fixture-wave2_checkpoint_independent-261-{}",
            serial()
        ))?),
        vec![transition(
            &i,
            3,
            ProcessState::Running,
            ProcessState::StopRequested,
            first.primary_event,
        )?],
    )?)?)??;
    assert_eq!(head(f, i.record.clone())?.revision.value.get(), 4);
    Ok(())
}
