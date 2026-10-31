use crate::*;
/// Protects: private host startup — absent and mismatched persisted machine identity refuses before creating a native child, identity record or endpoint.
pub fn private_startup_refuses_missing_and_mismatched_machine() -> Check {
    let f = std::mem::ManuallyDrop::new(Fixture::new()?);
    let (direct, lease) = f.direct()?;
    drop(direct);
    drop(lease);
    let configuration = f.options.state_directory.join("config.toml");
    let proposed = MachineId::new(uuid::Uuid::new_v4().to_string())?;
    let absent: Box<host::StartupFailure> = host::start(
        &f.options.state_directory,
        &configuration,
        proposed.clone(),
        &bound()?,
    )
    .err()
    .ok_or("startup generated a missing machine identity")?;
    assert!(absent.child.is_none());
    assert!(
        !f.options
            .state_directory
            .join("machine.json")
            .try_exists()?
    );
    let actual = route::identity::ensure_machine_identity(&f.options.state_directory)?;
    let before = std::fs::read(f.options.state_directory.join("machine.json"))?;
    assert_ne!(actual, proposed);
    let mismatch = host::start(
        &f.options.state_directory,
        &configuration,
        proposed,
        &bound()?,
    )
    .err()
    .ok_or("startup accepted a mismatched machine identity")?;
    assert!(mismatch.child.is_none());
    assert_eq!(
        std::fs::read(f.options.state_directory.join("machine.json"))?,
        before
    );
    assert!(
        !f.options
            .state_directory
            .join("endpoint.json")
            .try_exists()?
    );
    println!("PASS private_startup_refuses_missing_and_mismatched_machine");
    drop(std::mem::ManuallyDrop::into_inner(f));
    Ok(())
}

/// Protects: detached E3 entry — authenticated inherited bootstrap starts the exact persisted machine owner, serves a real owner request and retires endpoint/storage before the native process exits.
pub fn private_startup_serves_and_retires() -> Check {
    let f = std::mem::ManuallyDrop::new(Fixture::new()?);
    println!("CASE private startup fixture {}", f.home.display());
    let (mut direct, lease) = f.direct()?;
    direct.append(
        f.batch(
            f.owner_project(),
            None,
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
    drop(direct);
    drop(lease);
    let machine = route::identity::ensure_machine_identity(&f.options.state_directory)?;
    let before = std::fs::read(f.options.state_directory.join("machine.json"))?;
    let credential = secret()?;
    publish(&f, "credential", credential.expose())?;
    let ready: host::StartedHost = match host::start(
        &f.options.state_directory,
        &f.options.state_directory.join("config.toml"),
        machine.clone(),
        &bound()?,
    ) {
        Ok(value) => value,
        Err(failure) => {
            eprintln!(
                "retained failed startup fixture {} child={:?}",
                f.home.display(),
                failure.child.as_ref().and_then(|child| child.identity())
            );
            return Err(format!("private startup: {failure:?}").into());
        }
    };
    let _cleanup = ChildCleanup {
        endpoint: &ready.endpoint,
        identity: &ready.ready.identity,
        credential: &credential,
    };
    assert_eq!(ready.ready.identity.machine, machine);
    assert_eq!(ready.endpoint.epoch.owner.fields().machine, machine);
    assert_eq!(
        ready.endpoint.epoch.owner.fields().pid.get(),
        ready.ready.identity.pid.0
    );
    #[cfg(target_os = "linux")]
    assert!(matches!(
        ready.ready.detachment,
        se_proc::RuntimeDetachment::SessionOnly { .. }
    ));
    let published = match &ready.detachment_record {
        Read::Present { value } => value,
        _ => return Err("native detachment publication missing".into()),
    };
    let readback = present(host::read_detachment(
        &f.options.state_directory,
        &ready.endpoint,
        &bound()?,
    )?)?;
    assert_eq!(
        serde_json::to_value(&readback)?,
        serde_json::to_value(published)?
    );
    let mut stale = ready.endpoint.clone();
    stale.generation = se_types::Generation::new(ready.endpoint.generation.get() + 1)?;
    assert!(host::read_detachment(&f.options.state_directory, &stale, &bound()?).is_err());
    let selected = se_core::ops::CliSelections {
        project: Some(f.project.clone()),
        ..Default::default()
    };
    let outcome = ipc::forward(
        &ready.endpoint,
        se_host::client::lease::ClientCredential::Machine(copy_secret(&credential)?),
        se_core::ops::AnyOp::MessageSend(se_core::ops::MessageSend {
            to: f.b.as_str().into(),
            body: "detached native message".into(),
            kind: Default::default(),
            refs: vec![],
            reply_to: None,
            idempotency_key: key("detached-message")?,
        }),
        &selected,
        None,
        &options(),
    )
    .map_err(|error| format!("private startup owner message: {error}"));
    let reader = database_check(
        &f,
        "private live reader open",
        SqliteFactory::open_reader(&f.options),
    )
    .and_then(present)?;
    let unchanged_head =
        database_check(&f, "private live head before security", reader.info())?.head;
    let security_results = [
        ("profile", "default"),
        ("model", "unattested-model"),
        ("can-create", "true"),
    ]
    .into_iter()
    .map(|(field, value)| {
        ipc::forward(
            &ready.endpoint,
            se_host::client::lease::ClientCredential::Machine(copy_secret(&credential)?),
            se_core::ops::AnyOp::ConfigSet(se_core::ops::ConfigSet {
                key: format!("agent.{}.{}", f.a, field),
                value: value.into(),
                idempotency_key: key(&format!("no-presence-{field}"))?,
            }),
            &selected,
            None,
            &options(),
        )
        .map(|_| ())
        .map_err(|error| error.into())
    })
    .collect::<Vec<Check>>();
    let after_security =
        database_check(&f, "private live head after security", reader.info())?.head;
    drop(reader);
    let presence_outcome = presence_judge::clients(&f).map_err(|error| {
        format!("private startup presence controls/outside grant readback: {error}")
    });
    stop_native(&ready.endpoint, &credential, "detached-stop")
        .map_err(|error| format!("private startup storage stop: {error}"))?;
    wait_native_exit(&ready.ready.identity)
        .map_err(|error| format!("private startup native exit: {error}"))?;
    outcome?;
    presence_outcome?;
    assert_eq!(
        unchanged_head, after_security,
        "unattested security call wrote an event"
    );
    for result in security_results {
        let error = result
            .err()
            .ok_or("security-key host write accepted without the native presence pair")?;
        let error = error
            .downcast_ref::<se_types::SeError>()
            .ok_or("security key refused for an unexpected test/setup error")?;
        assert!(
            matches!(
                error.body.detail(),
                se_types::Detail::HumanTerminalRequired(_)
            ),
            "security key refused for the wrong reason: {error}"
        );
    }
    assert_eq!(
        std::fs::read(f.options.state_directory.join("machine.json"))?,
        before
    );
    assert!(
        !f.options
            .state_directory
            .join("endpoint.json")
            .try_exists()?
    );
    let reader = database_check(
        &f,
        "private post-stop reader open",
        SqliteFactory::open_reader(&f.options),
    )
    .and_then(present)?;
    let mut read = database_check(
        &f,
        "private post-stop message snapshot",
        reader.snapshot(f.self_scope(&f.b)),
    )?;
    let messages = database_check(
        &f,
        "private post-stop message page",
        read.messages(query(None, false), budget(10, 65536, None)?),
    )?;
    assert_eq!(messages.items().len(), 1);
    assert!(
        matches!(messages.items()[0].body,StoredText::Present(ref text) if text=="detached native message")
    );
    read.close()?;
    drop(reader);
    drop(Lease::acquire(
        &f.options.state_directory,
        LeaseMode::Host,
        Some(f.store.clone()),
    )?);
    println!(
        "PASS private_startup_serves_and_retires: exact native owner, persisted machine, real message, pending full shutdown, outside exit and lease witnesses"
    );
    drop(_cleanup);
    drop(std::mem::ManuallyDrop::into_inner(f));
    Ok(())
}
