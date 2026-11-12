//! Reviewer controls: batching must retain rendered-only cursors and fair target service.
use super::*;
use crate::runtime::test_support as support;
use crate::{HostedRuntime, initialize_host_process};
use support::{Check, Fixture};
fn run(control: impl FnOnce(&Service, &Fixture, u64) -> Check) -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    support::seed(&f)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
        let mut runtime = HostedRuntime::prepare(
            initialized,
            support::start(&f)?,
            rt.handle().clone(),
            &support::bound()?,
        )
        .await?;
        let listener = runtime
            .listen(rt.handle().clone(), &support::bound()?)
            .await?;
        let execution = runtime.execution_context();
        let mut admission = f.admission(
            se_store::Scope::Registry,
            se_store::Actor::Human(f.owner.clone()),
        );
        admission.generation = execution.generation.get();
        let owner = auth::VerifiedLocalOwner::from_machine(&admission)?;
        let files = Arc::new(crate::state_files::Files::open(&f.options.state_directory)?);
        let cipher = Arc::new(keys::CursorCipher::initialize(
            &owner,
            files,
            f.options.state_directory.clone(),
        )?);
        let live = publish::LivePublisher::new(RemoteInstanceId([17; 16]))?;
        let security = Arc::new(session::SecurityStore::new(
            execution.reader.as_ref().clone(),
            execution.writer.clone(),
            execution.generation.get(),
            f.owner.clone(),
        )?);
        let service = Service::new(
            runtime.router()?,
            security,
            live,
            cipher,
            RemoteHostId(se_types::Sha256::from_bytes([19; 32])),
        );
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            control(&service, &f, execution.generation.get())
        }));
        drop(service);
        drop(execution);
        runtime.local_stop().request();
        let exit = runtime.serve(listener).await;
        let report = exit.finish(&support::bound()?).await;
        assert!(
            report.transport_closed && report.endpoint_retired,
            "native runtime did not retire"
        );
        assert!(
            matches!(report.storage, se_types::Read::Present {ref value} if value.writer_joined),
            "writer did not join"
        );
        match result {
            Ok(result) => result,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    })
}
fn state(
    service: &Service,
    f: &Fixture,
    generation: u64,
    budget: u32,
    targets: Vec<RemoteTarget>,
) -> std::result::Result<State, Box<dyn std::error::Error>> {
    let input = RemoteWatch {
        visible: targets.first().cloned(),
        targets,
        cursors: vec![],
        budget,
        measure: true,
    };
    let mut admission = f.admission(
        se_store::Scope::Registry,
        se_store::Actor::Human(f.owner.clone()),
    );
    admission.generation = generation;
    let request = Arc::new(view_request::ViewRequest::local(admission, input.clone())?);
    Ok(State {
        request,
        input,
        positions: BTreeMap::new(),
        manifest: false,
        manifest_after: None,
        initial: false,
        offset: 0,
        durable_revision: Some(service.live.commit_revision()),
    })
}
fn source(
    service: &Service,
    target: RemoteTarget,
) -> std::result::Result<publish::LiveSource, Box<dyn std::error::Error>> {
    Ok(service.live.register(
        target,
        se_types::SessionId::from_parts(1_700_000_000_000, [21; 10])?,
        se_types::LifecycleId::from_parts(1_700_000_000_000, [22; 10])?,
        se_types::Generation::new(1)?,
    )?)
}
fn checked(
    state: &mut State,
    service: &Service,
) -> std::result::Result<RemoteWatchBatch, Box<dyn std::error::Error>> {
    let (batch, _) = state.drain(service)?;
    assert!(
        wire::encode(&batch, wire::Phase::Authenticated)?.len() <= state.input.budget as usize,
        "encoded page exceeded budget"
    );
    for cursor in &batch.cursors {
        if let Some(live) = &cursor.live {
            let position: publish::LivePosition =
                service
                    .cursors
                    .decoded(&state.request, Some(&cursor.target), "live", live)?;
            let rendered = batch
                .records
                .iter()
                .rev()
                .find_map(|record| match record {
                    RemoteWatchRecord::Provisional { target, item, .. }
                        if target == &cursor.target =>
                    {
                        Some(item.item_id.as_str())
                    }
                    _ => None,
                })
                .ok_or("cursor without a rendered provisional item")?;
            assert_eq!(
                rendered,
                format!("item-{}", position.sequence),
                "cursor skipped unrendered output"
            );
        }
    }
    Ok(batch)
}
#[test]
fn ready_observations_share_one_encoded_page() -> Check {
    run(|service, f, generation| {
        let target = RemoteTarget {
            project: f.project.clone(),
            agent: f.a.clone(),
        };
        let source = source(service, target.clone())?;
        let mut state = state(service, f, generation, 65_536, vec![target])?;
        for index in 1..=12 {
            source.complete(
                &format!("item-{index}"),
                RemoteTurnRole::Assistant,
                "ready output",
            );
        }
        let batch = checked(&mut state, service)?;
        assert_eq!(
            batch.records.len(),
            12,
            "ready output was throttled to one item per page"
        );
        assert!(batch.complete);
        assert!(
            checked(&mut state, service)?.records.is_empty(),
            "rendered output replayed"
        );
        Ok(())
    })
}
#[test]
fn full_visible_backlog_cannot_starve_selected_targets_or_skip_a_cursor() -> Check {
    run(|service, f, generation| {
        let targets = [f.a.clone(), f.b.clone(), support::agent()?]
            .into_iter()
            .map(|agent| RemoteTarget {
                project: f.project.clone(),
                agent,
            })
            .collect::<Vec<_>>();
        let sources = targets
            .iter()
            .map(|target| source(service, target.clone()))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let mut state = state(service, f, generation, 8192, targets.clone())?;
        for source in &sources {
            for index in 1..=10 {
                source.complete(
                    &format!("item-{index}"),
                    RemoteTurnRole::Assistant,
                    &"x".repeat(3900),
                );
            }
        }
        let mut seen = BTreeMap::<RemoteTarget, Vec<String>>::new();
        for page in 0..36 {
            let batch = checked(&mut state, service)?;
            for record in &batch.records {
                if let RemoteWatchRecord::Provisional { target, item, .. } = record {
                    seen.entry(target.clone())
                        .or_default()
                        .push(item.item_id.clone());
                }
            }
            if page == 2 {
                assert!(
                    targets.iter().all(|target| seen.contains_key(target)),
                    "visible backlog starved a selected target for a full rotation"
                );
            }
            if page == 4 {
                // Reconnect through the production cursor decoder, retaining only
                // the last rendered position for each previously seen target.
                state.input.cursors = state
                    .positions
                    .values()
                    .filter_map(|position| position.wire.clone())
                    .collect();
                state.positions.clear();
                state.initial = true;
            }
            if batch.complete {
                break;
            }
        }
        for target in targets {
            assert_eq!(
                seen.get(&target),
                Some(&(1..=10).map(|n| format!("item-{n}")).collect::<Vec<_>>()),
                "hidden, duplicated or skipped output"
            );
        }
        assert!(checked(&mut state, service)?.complete);
        Ok(())
    })
}

/// Protects: local live output stays well inside the 75 ms target end to end.
///
/// The producer stamps the observation, the publisher folds it into the ring,
/// and a watcher page carries it back with the observation clock, so this
/// measures emission -> fold -> page on the real path rather than a stand-in.
/// A regression that reintroduces a poll interval or a sleep in that path
/// shows up here as a page that misses the bound.
#[test]
fn local_live_output_reaches_a_watcher_page_well_inside_the_target() -> Check {
    run(|service, f, generation| {
        let target = RemoteTarget {
            project: f.project.clone(),
            agent: f.a.clone(),
        };
        let source = source(service, target.clone())?;
        let mut state = state(service, f, generation, 65_536, vec![target])?;
        let mut worst = std::time::Duration::ZERO;
        for index in 1..=20 {
            let started = std::time::Instant::now();
            source.complete(
                &format!("item-{index}"),
                RemoteTurnRole::Assistant,
                "streamed output",
            );
            let batch = checked(&mut state, service)?;
            worst = worst.max(started.elapsed());
            assert!(
                batch
                    .records
                    .iter()
                    .any(|record| matches!(record, RemoteWatchRecord::Provisional { .. })),
                "the page carried no provisional item for item-{index}"
            );
        }
        eprintln!("local live output: worst emission-to-page {worst:?}");
        assert!(
            worst < Duration::from_millis(75),
            "emission-to-page took {worst:?}, over the 75 ms target"
        );
        Ok(())
    })
}
