#![allow(
    dead_code,
    reason = "The shared real native fixture supports several public API consumers."
)]
use se_store::*;
use se_types::Read;
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
#[path = "support/history_cli.rs"]
mod history_cli;
use fixture::*;

/// Protects: a separate CLI process reads the original exact committed body, actor and direct writer after later commits, with opaque positions and no raw storage order.
#[test]
fn original_event_is_readable_after_later_commits() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let receipt = store.append(
        f.working("original unicode 🦀", Expected::Absent, "original")?,
        &*lease,
    )?;
    store.append(f.working("newer content", revision(1)?, "newer")?, &*lease)?;
    let head = store.info()?.head;
    for _ in 0..2 {
        let (output, value) = history_cli::read(
            &f.options.state_directory,
            &f.project,
            &receipt.primary_event,
        )?;
        assert!(
            output.status.success(),
            "actual history CLI: {value}; {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(value["schema"], "se.event/v1");
        assert_eq!(value["event_id"], receipt.primary_event.as_str());
        assert_eq!(value["kind"], "working_state.set");
        assert_eq!(value["actor"]["id"], f.a.as_str());
        assert_eq!(value["project"]["id"], f.project.as_str());
        assert_eq!(value["writer"]["mode"], "direct");
        assert_eq!(value["payload"]["body"]["text"], "original unicode 🦀");
        assert_eq!(
            value["payload"]["body"]["bytes"],
            "original unicode 🦀".len()
        );
        assert_eq!(value["payload"]["body"]["complete"], true);
        assert_eq!(value["payload"]["revision"], 1);
        for name in ["position", "read_at", "recorded_at"] {
            assert!(
                value[name].as_str().is_some_and(|value| !value.is_empty()),
                "missing opaque/time field {name}"
            );
        }
        for name in ["seq", "last_seq", "generation", "credential", "custody"] {
            assert!(
                value.get(name).is_none(),
                "raw/private storage field {name}"
            );
        }
    }
    assert_eq!(store.info()?.head, head);
    store.close()?;
    Ok(())
}

/// Protects: unknown exact IDs retain successful measured absence rather than a fabricated event or a refusal.
#[test]
fn unknown_event_is_absent_without_effects() -> Check {
    let f = Fixture::new()?;
    let (store, lease) = f.direct()?;
    let head = store.info()?.head;
    let (output, value) = history_cli::read(&f.options.state_directory, &f.project, &event()?)?;
    assert!(output.status.success(), "unknown history refused: {value}");
    assert_eq!(value["schema"], "se.event/v1");
    assert_eq!(value["state"], "absent");
    assert!(value.get("payload").is_none());
    assert_eq!(store.info()?.head, head);
    store.close()?;
    drop(lease);
    Ok(())
}

/// Protects: a known foreign exact ID is a typed public scope refusal and remains distinct from the same reader's genuine not-found result.
#[test]
fn foreign_known_id_is_not_not_found() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    let foreign = se_types::ProjectId::from_parts(1_700_000_000_000 + serial(), [79; 10])?;
    let receipt = store.append(
        f.batch(
            f.admission(
                Scope::Project(foreign.clone()),
                Actor::Human(f.owner.clone()),
            ),
            Some(fixture::request(&format!(
                "fixture-history_event-90-{}",
                serial()
            ))?),
            vec![EventBody::ProjectRegistered {
                project: foreign,
                name: "Foreign".into(),
                roots: vec![],
                owner: f.owner.clone(),
                history_from: None,
                expected: Expected::Absent,
            }],
        )?,
        &*lease,
    )?;
    let (output, value) = history_cli::read(
        &f.options.state_directory,
        &f.project,
        &receipt.primary_event,
    )?;
    assert!(
        !output.status.success(),
        "known foreign ID became absence: {value}"
    );
    assert_eq!(value["code"], "capability-invalid");
    assert!(value.get("payload").is_none());
    store.close()?;
    drop(lease);
    Ok(())
}

/// Protects: generated CLI and tool metadata share the authorized-project read-only event family.
#[test]
fn event_catalogue_keeps_read_only_project_contract() -> Check {
    let op = se_core::ops::AnyOp::EventRead(se_core::ops::EventRead {
        event_id: event()?.to_string(),
    });
    let meta = op.meta();
    assert_eq!(meta.name, "history.event_read");
    assert_eq!(meta.effect, se_core::registry::Effect::Read);
    assert_eq!(meta.scope, se_core::registry::Scope::Project);
    assert!(matches!(
        meta.mcp,
        se_core::registry::McpExposure::Tool {
            name: "stateengine_event_read",
            ..
        }
    ));
    let f = Fixture::new()?;
    assert!(matches!(
        SqliteFactory::open_reader(&f.options)?,
        Read::Absent { .. }
    ));
    Ok(())
}

/// Protects: actual damaged protected store bytes map to the public StoreCorrupt family with a relative database path, preserving the source for diagnosis.
#[test]
fn corrupt_store_retains_public_integrity_code() -> Check {
    use std::io::Write;
    let f = Fixture::new()?;
    let files = se_proc::NativeStateFiles::open(&f.options.state_directory)?;
    let mut stage = files.create_staging(&f.options.state_directory)?;
    stage.file.write_all(b"damaged SQLite header")?;
    stage.file.sync_all()?;
    drop(stage.file);
    let path = f.options.state_directory.join("state.db");
    files.publish_no_replace(&stage.path, &path)?;
    let (output, value) = history_cli::read(&f.options.state_directory, &f.project, &event()?)?;
    assert!(
        !output.status.success(),
        "corruption became an event or absence: {value}"
    );
    assert_eq!(value["code"], "store-corrupt");
    assert_eq!(value["detail"]["path"], "state.db");
    assert_eq!(std::fs::read(path)?, b"damaged SQLite header");
    Ok(())
}

/// Protects: default event inspection shows a registration's public subject and role instead of dropping all non-body payload fields that --json preserves.
#[test]
fn default_output_keeps_registration_payload() -> Check {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    store.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request(&format!(
                "fixture-history_event-177-{}",
                serial()
            ))?),
            vec![EventBody::PrincipalRegistered {
                principal: Actor::Human(f.owner.clone()),
                kind: PrincipalKind::Human,
                owner: f.owner.clone(),
                created_by: None,
                name: "Owner".into(),
                role: "owner".into(),
                expected: Expected::Absent,
            }],
        )?,
        &*lease,
    )?;
    let mut snapshot = store.snapshot(f.scoped(Visibility::Owner))?;
    let principal = present(snapshot.principal(Actor::Agent(f.a.clone()))?)?;
    let id = principal.current.header.event;
    snapshot.close()?;
    let (json, value) = history_cli::read(&f.options.state_directory, &f.project, &id)?;
    assert!(
        json.status.success(),
        "registration readback failed: {value}"
    );
    assert_eq!(value["payload"]["name"], "Sable");
    assert_eq!(value["payload"]["role"], "builder");
    let human = history_cli::human(&f.options.state_directory, &f.project, &id)?;
    let text = String::from_utf8(human.stdout)?;
    assert!(
        human.status.success(),
        "default history read refused: {}",
        String::from_utf8_lossy(&human.stderr)
    );
    assert!(
        text.contains("Sable") && text.to_lowercase().contains("builder"),
        "default history lost registration payload: {text}"
    );
    store.close()?;
    drop(lease);
    Ok(())
}
