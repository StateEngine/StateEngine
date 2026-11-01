use crate::*;
use se_core::ops::{AnyOp, CliSelections};
use se_types::{AgentId, EventId};
use std::sync::Barrier;

const CLIENTS: usize = 8;
const ROUNDS: u64 = 30;
struct Proof {
    event: EventId,
    agent: AgentId,
    body: String,
    working: bool,
    revision: u64,
}

/// Protects: eight finite host jobs have matching reader capacity during real
/// authenticated planning and post-commit continuation. Every write must return
/// its receipt and independently read back; neither refusal nor a confirmed
/// commit with an unavailable response counts as successful behavior.
pub fn check() -> Check {
    let initialized = se_host::initialize_host_process()?;
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let agents: Vec<_> = (0..CLIENTS).map(|_| agent()).collect::<Result<_, _>>()?;
    for (index, agent) in agents.iter().enumerate() {
        direct.append(
            f.batch(
                f.owner_project(),
                None,
                vec![EventBody::PrincipalRegistered {
                    principal: Actor::Agent(agent.clone()),
                    kind: PrincipalKind::Agent,
                    owner: f.owner.clone(),
                    created_by: None,
                    name: format!("Concurrent {index}"),
                    role: "builder".into(),
                    expected: Expected::Absent,
                }],
            )?,
            lease.as_ref(),
        )?;
    }
    drop(direct);
    drop(lease);
    let machine = route::identity::ensure_machine_identity(&f.options.state_directory)?;
    let credential = secret()?;
    publish(&f, "credential", credential.expose())?;
    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(CLIENTS)
        .build()?;
    let proofs = engine.block_on(async {
        let mut start = start_options(&f, epoch(machine)?)?;
        start.limits.blocking_jobs = positive(CLIENTS as u32)?;
        start.limits.active_connections = positive(32)?;
        start.limits.preauth_connections = positive(16)?;
        let mut runtime =
            se_host::HostedRuntime::prepare(initialized, start, engine.handle().clone(), &bound()?)
                .await?;
        assert_eq!(
            runtime
                .blocking_pool()
                .foreground_admission()
                .available_permits(),
            CLIENTS,
            "this consumer must exercise eight actual finite slots"
        );
        runtime.configure(se_core::config_policy::ConfigFile::default())?;
        let listener = runtime.listen(engine.handle().clone(), &bound()?).await?;
        let endpoint = listener.endpoint().clone();
        let owner_key = copy_secret(&credential)?;
        let project = f.project.clone();
        let coordinator = std::thread::spawn(move || {
            let barrier = Arc::new(Barrier::new(CLIENTS));
            let mut clients = Vec::new();
            for (index, agent) in agents.into_iter().enumerate() {
                let endpoint = endpoint.clone();
                let project = project.clone();
                let barrier = barrier.clone();
                let key_bytes = owner_key.expose().to_vec();
                clients.push(std::thread::spawn(move || {
                    let mut proofs = Vec::new();
                    let mut failures = Vec::new();
                    for working in [false, true] {
                        for round in 0..ROUNDS {
                            barrier.wait();
                            match write(
                                &endpoint, &key_bytes, &project, &agent, index, round, working,
                            ) {
                                Ok(proof) => proofs.push(proof),
                                Err(error) => failures.push(format!(
                                    "client={index} round={round} working={working}: {error}"
                                )),
                            }
                        }
                    }
                    (proofs, failures)
                }));
            }
            let mut proofs = Vec::new();
            let mut failures = Vec::new();
            for client in clients {
                match client.join() {
                    Ok((mut rows, mut errors)) => {
                        proofs.append(&mut rows);
                        failures.append(&mut errors);
                    }
                    Err(_) => failures.push("eight-client worker panicked".into()),
                }
            }
            // Always retire the host before reporting a failed write, so a red
            // judge does not abandon the native listener or its writer.
            let stopped = stop_native(&endpoint, &owner_key, "eight-clients-stop")
                .map_err(|error| error.to_string());
            (proofs, failures, stopped)
        });
        let exit = tokio::time::timeout(Duration::from_secs(120), runtime.serve(listener))
            .await
            .map_err(|_| "eight-client supervisor failed to receive stop")?;
        let outcome = exit.finish(&bound()?).await;
        let (proofs, failures, stopped) = coordinator
            .join()
            .map_err(|_| "eight-client coordinator panicked")?;
        stopped?;
        assert!(outcome.transport_closed && outcome.endpoint_retired);
        assert!(
            outcome.errors.is_empty(),
            "shutdown errors: {:?}",
            outcome.errors
        );
        assert!(
            failures.is_empty(),
            "eight-client write failures: {failures:#?}"
        );
        assert_eq!(proofs.len(), CLIENTS * ROUNDS as usize * 2);
        Ok::<_, Box<dyn std::error::Error>>(proofs)
    })?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let mut snapshot = reader.snapshot(f.scoped(Visibility::Owner))?;
    let mut events = std::collections::BTreeSet::new();
    for proof in &proofs {
        assert!(
            events.insert(proof.event.clone()),
            "replay created a second effect"
        );
        let event = present(snapshot.event(proof.event.clone())?)?;
        match event.body {
            EventBody::WorkingStateSet {
                agent,
                text: StoredText::Present(text),
                ..
            } if proof.working => {
                assert_eq!(agent, proof.agent);
                assert_eq!(text, proof.body);
            }
            EventBody::MessageSent {
                recipient,
                body: StoredText::Present(text),
                ..
            } if !proof.working => {
                assert_eq!(recipient, Actor::Agent(proof.agent.clone()));
                assert_eq!(text, proof.body);
            }
            other => return Err(format!("unexpected concurrent event: {other:?}").into()),
        }
        if proof.working && proof.revision == ROUNDS {
            let state = present(snapshot.working_state(proof.agent.clone())?)?;
            assert_eq!(state.revision.value.get(), ROUNDS);
            assert!(matches!(state.current.body,
                EventBody::WorkingStateSet { text: StoredText::Present(ref text), .. }
                if text == &proof.body));
        }
    }
    snapshot.close()?;
    drop(reader);
    drop(Lease::acquire(
        &f.options.state_directory,
        LeaseMode::Host,
        Some(f.store.clone()),
    )?);
    println!(
        "PASS eight_clients: eight actual slots, 480 authenticated writes and continuations, 16 exact replays, outside event/state readback and retired lease"
    );
    Ok(())
}

fn write(
    endpoint: &se_host::EndpointRecord,
    credential: &[u8],
    project: &se_types::ProjectId,
    agent: &AgentId,
    index: usize,
    round: u64,
    working: bool,
) -> CheckProof {
    let body = format!("eight-client-{index}-{working}-{round}");
    let request = key(&body)?;
    let selected = CliSelections {
        project: Some(project.clone()),
        agent: working.then(|| agent.as_str().into()),
        ..Default::default()
    };
    let operation = || {
        if working {
            AnyOp::WorkingStateSet(se_core::ops::WorkingStateSet {
                text: body.clone(),
                expect: if round == 0 {
                    se_core::commit::ExpectedRevision::Absent(
                        se_core::commit::AbsentRevision::Absent,
                    )
                } else {
                    se_core::commit::ExpectedRevision::Revision(round)
                },
                idempotency_key: request.clone(),
                owner_agent: None,
            })
        } else {
            AnyOp::MessageSend(se_core::ops::MessageSend {
                to: agent.as_str().into(),
                body: body.clone(),
                kind: Default::default(),
                refs: vec![],
                reply_to: None,
                idempotency_key: request.clone(),
            })
        }
    };
    let call = || {
        ipc::forward(
            endpoint,
            se_host::client::lease::ClientCredential::Machine(Secret::new(credential.to_vec())?),
            operation(),
            &selected,
            None,
            &options(),
        )
    };
    let output = serde_json::to_value(call().map_err(|error| {
        // Keep refusal and confirmed-commit failure distinct in the red output.
        format!("{}: {}", error.code().as_str(), error)
    })?)?;
    if output["state"] != "committed"
        || output["writer"]["mode"] != "host"
        || output["idempotency_key"] != request.as_str()
        || !output["diagnostics"]["write_timings"].is_object()
    {
        return Err(
            format!("concurrent receipt missing committed identity/timings: {output}").into(),
        );
    }
    if working && output["revision"] != round + 1 {
        return Err(format!("unexpected working revision: {output}").into());
    }
    if round == 0 {
        let replay = serde_json::to_value(call()?)?;
        if replay["state"] != "replayed" || replay["event_id"] != output["event_id"] {
            return Err(format!("concurrent replay changed the effect: {replay}").into());
        }
    }
    Ok(Proof {
        event: output["event_id"]
            .as_str()
            .ok_or("concurrent event ID")?
            .parse()?,
        agent: agent.clone(),
        body,
        working,
        revision: round + 1,
    })
}
type CheckProof = Result<Proof, Box<dyn std::error::Error>>;
