//! Real cold child -> owner controller -> IPC -> admitted core/query consumers.
//! The development SQL profile exercises behavior, not steady-memory qualification.
// Debug's mapped image alone exceeds the cold worker's 64 MB address cap.
// Native execution is checked with cargo test --release --test atlas_owner_route.
#![cfg(all(
    any(target_os = "linux", windows, target_os = "macos"),
    not(debug_assertions)
))]
use se_atlas::{
    cache::connection::*, controller::Step, errors::AtlasResult, lifecycle::*, model::*,
    scheduler::Scheduled, source::RegisteredSource,
};
use se_host::{
    atlas_runtime::{
        NativeController, NativeRuntime, RenewalDriver, drive_child, read_port::ControllerReadPort,
        record_fence::RecordFeedScope,
    },
    atlas_source::NativeAtlasSource,
    *,
};
use se_store::*;
use se_types::{
    HostEpoch, HostGeneration, MachineId, ProcessFields, ProcessInstance, Secret, code::*,
};
use std::{
    fs,
    io::Write,
    num::{NonZeroU16, NonZeroU32},
    path::PathBuf,
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::{Duration, Instant},
};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(
    dead_code,
    reason = "Only typed session event constructors are needed."
)]
mod session;
struct ColdOnly;
impl RenewalDriver for ColdOnly {
    fn step(
        &mut self,
        _: &RegisteredSource<NativeAtlasSource>,
        _: &CacheConnection<'_>,
        _: &AtlasPolicy,
        _: &Scheduled,
        _: Instant,
    ) -> AtlasResult<Step> {
        Err(se_types::SeError::invalid(
            "native route test",
            "cold-only driver cannot renew",
        ))
    }
    fn poll_events(
        &mut self,
        _: &RegisteredSource<NativeAtlasSource>,
        _: &CacheConnection<'_>,
        _: &AtlasPolicy,
        _: Instant,
    ) -> AtlasResult<Vec<SourceHint>> {
        Err(se_types::SeError::invalid(
            "native route test",
            "native watcher belongs to renewal qualification",
        ))
    }
    fn close(
        &mut self,
        _: &RootId,
        _: Option<&CacheConnection<'_>>,
        _: Instant,
    ) -> AtlasResult<()> {
        Ok(())
    }
}
fn positive(n: u32) -> Result<NonZeroU32, Box<dyn std::error::Error>> {
    NonZeroU32::new(n).ok_or_else(|| "zero test bound".into())
}
fn client_options() -> client::ClientOptions {
    client::ClientOptions {
        expected_generation: None,
        timeout: Duration::from_secs(10),
        cancelled: Arc::new(AtomicBool::new(false)),
    }
}
fn deadline() -> Result<client::lease::Deadline, Box<dyn std::error::Error>> {
    Ok(client::lease::Deadline::from_options(&client_options())?)
}
fn start(f: &Fixture) -> Result<HostStart, Box<dyn std::error::Error>> {
    let machine = MachineId::new("atlas-owner-native-consumer")?;
    #[cfg(any(target_os = "linux", windows))]
    let boot = se_proc::current_runtime_identity(machine.clone())
        .map_err(|e| format!("runtime observation: {e:?}"))?
        .boot_id;
    #[cfg(target_os = "macos")]
    let boot = se_proc::observe_boot_id()?;
    let peer = se_proc::native_ipc::observe_ipc_self()?;
    Ok(HostStart {
        state_directory: f.options.state_directory.clone(),
        epoch: HostEpoch {
            owner: ProcessInstance::from_observation(ProcessFields {
                machine,
                boot,
                pid: positive(peer.pid())?,
                started: peer.started().clone(),
                executable: peer.image().clone(),
                argv_sha256: se_types::Sha256::from_bytes([0; 32]),
            })?,
            generation: HostGeneration::new(1)?,
        },
        kind: HostKind::Standalone,
        writer: WriterOptions {
            maximum_requests: NonZeroU16::new(16).ok_or("requests")?,
            queue_requests: NonZeroU16::new(16).ok_or("queue")?,
            resident_bytes: positive(1048576)?,
            group_bytes: positive(1048576)?,
        },
        limits: HostLimits {
            sessions: positive(2)?,
            active_connections: positive(2)?,
            preauth_connections: positive(2)?,
            parked_mail_waits: positive(2)?,
            resident_queue_bytes: positive(1048576)?,
            session_notice_ids: positive(16)?,
            aggregate_notice_ids: positive(32)?,
            response_bytes: positive(1048576)?,
            blocking_jobs: positive(2)?,
        },
    })
}
fn policy() -> AtlasPolicy {
    AtlasPolicy {
        enabled: true,
        max_files: 100,
        parse: ParseBudget {
            max_source_bytes: 524288,
            max_rows: 65536,
            max_work: Duration::from_millis(200),
            reserved_bytes: 1_000_000,
        },
        total_reserved_bytes: 2_000_000,
        change_retention_days: 30,
        max_change_rows: 50_000,
        max_cache_bytes: 128_000_000,
        ignore: IgnorePolicy {
            global_patterns: vec![],
            generated_prefixes: vec![],
            digest: ContentHash([0; 32]),
        },
        watch: WatchBudget {
            max_directories: 0,
            max_mapping_bytes: 0,
            observed_os_limit: None,
        },
    }
}
fn exchange(
    endpoint: &se_host::EndpointRecord,
    project: se_types::ProjectId,
    name: &str,
    arguments: serde_json::Value,
) -> Result<se_core::ops::AnyOutput, Box<dyn std::error::Error>> {
    exchange_as(
        endpoint,
        project,
        name,
        arguments,
        client::lease::ClientCredential::Machine(Secret::new(vec![23; 32])?),
    )
}
fn exchange_as(
    endpoint: &se_host::EndpointRecord,
    project: se_types::ProjectId,
    name: &str,
    arguments: serde_json::Value,
    credential: client::lease::ClientCredential,
) -> Result<se_core::ops::AnyOutput, Box<dyn std::error::Error>> {
    let options = client_options();
    let mut client = client::BlockingIpcClient::connect_authenticated(
        endpoint,
        credential,
        positive(32768)?,
        &options,
    )?;
    let response = client.exchange(
        IpcEnvelope {
            version: client.negotiated().version,
            request_id: 1,
            generation: endpoint.generation,
            authority: None,
            presence: None,
            cli_selections: Some(serde_json::to_value(se_core::ops::CliSelections {
                project: Some(project),
                ..Default::default()
            })?),
            request: IpcRequest::Operation(RawOperation {
                name: name.into(),
                arguments,
                key: None,
            }),
        },
        &options,
    )?;
    let mut value = response.value;
    value["schema"] = response.schema.into();
    Ok(serde_json::from_value(value)?)
}
// Only the optional hook's server-side ingress slice may expire. Public reads
// and the client's ten-second transport deadline must still succeed.
// Sub-millisecond remaining slices are serialized as zero milliseconds.
fn optional_hint_deadline(error: &(dyn std::error::Error + 'static)) -> bool {
    error
        .downcast_ref::<se_types::SeError>()
        .is_some_and(|error| {
            matches!(error.body.detail(), se_types::Detail::DeadlineExceeded(detail)
            if detail.op == "local IPC" && detail.deadline_ms <= 5)
        })
}
/// Protects: only the typed optional-hint ingress timeout is tolerated; all other failures stay visible.
#[test]
fn optional_hint_deadline_rejects_other_failures() {
    let timeout = |op: &str, deadline_ms| {
        se_types::SeError::new(se_types::Detail::DeadlineExceeded(
            se_types::details::DeadlineExceeded {
                op: op.into(),
                deadline_ms,
            },
        ))
    };
    for milliseconds in [0, 3, 5] {
        assert!(optional_hint_deadline(&timeout("local IPC", milliseconds)));
    }
    for error in [
        timeout("local IPC", 6),
        timeout("local IPC", 10_000),
        timeout("Atlas SQL", 3),
        se_types::SeError::invalid("authority", "the admitted session"),
        se_types::SeError::new(se_types::Detail::Cancelled(se_types::details::Cancelled {
            op: "local IPC".into(),
        })),
    ] {
        assert!(
            !optional_hint_deadline(&error),
            "unexpected tolerated error: {error}"
        );
    }
    assert!(
        !optional_hint_deadline(&std::io::Error::other(
            "atlas.augment: deadline-exceeded: local IPC didn't finish in 3 ms",
        )),
        "matching text without the typed error is not a legal timeout"
    );
}
/// Protects: a contained cold job is adopted and serves real owner IPC queries.
#[test]
fn five_queries_reach_the_real_owner_after_a_contained_cold_build() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    direct.append(
        f.send(
            Actor::Agent(f.a.clone()),
            Actor::Agent(f.a.clone()),
            message()?,
            "packet budget is discussed in alpha.rs",
            "atlas-native-record",
        )?,
        &*lease,
    )?;
    let files = se_proc::NativeStateFiles::open(&f.options.state_directory)?;
    let mut staged = files.create_staging(&f.options.state_directory)?;
    staged.file.write_all(&[23; 32])?;
    staged.file.sync_all()?;
    drop(staged.file);
    files.publish_no_replace(&staged.path, &f.options.state_directory.join("credential"))?;
    let source = f.home.join("source");
    fs::create_dir(&source)?;
    fs::write(
        source.join("alpha.rs"),
        "pub fn alpha() -> u32 { 1 }\npub fn getHTTPResponse2_id() {}\n",
    )?;
    fs::write(
        source.join("lib.rs"),
        "mod alpha;\npub fn caller() -> u32 { alpha::alpha() }\n",
    )?;
    fs::write(
        source.join("entry.js"),
        "function bootstrap() {}\nbootstrap();\n",
    )?;
    fs::write(
        source.join(".env.rs"),
        "pub fn atlas_private_native_marker() {}\n",
    )?;
    let atlas_home = f.home.join("atlas");
    let root = RootId::from_parts(1, [42; 10])?;
    let registration = RootRegistration {
        project: f.project.clone(),
        root: root.clone(),
        canonical_source_root: source,
        cache: CacheLocation {
            directory: atlas_home.join(f.project.as_str()).join(root.as_str()),
        },
        git_metadata: None,
    };
    let image = PathBuf::from(env!("CARGO_BIN_EXE_se")).canonicalize()?;
    let mut controller = NativeController::new(NativeRuntime::new(
        atlas_home,
        image,
        ColdOnly,
        Some(SqlProfile::from_qualified_overhead(1)?),
    )?);
    controller.register(registration.clone(), policy())?;
    controller.activate(root.clone(), ReconcileReason::FirstSession)?;
    if let NextWork::AfterEventDebounce(wait) = controller.next_work() {
        std::thread::sleep(wait);
    }
    controller.work_quantum(Duration::from_millis(200))?;
    drive_child(&mut controller)?;
    // ColdJob and its native worker own the finite completion/reap/adoption clock.
    // This functional route check also runs on loaded, slower native machines.
    while controller.runtime().child_pid().is_some() {
        controller
            .runtime_mut()
            .wait_child_ready(Instant::now() + Duration::from_millis(100))?;
        drive_child(&mut controller)?;
    }
    let index = controller.runtime().summary(&root)?;
    assert!(index.epoch.is_some(), "cold child did not publish an epoch");
    // Cold work must not consume the query session credential's useful lifetime.
    let id = session::session()?;
    let credential = session::record()?;
    let token = Secret::new(format!("sec1.{}.{}", id.as_str(), "A".repeat(43)).into_bytes())?;
    use sha2::{Digest, Sha256};
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros(),
    )?;
    direct.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("atlas-owner-session")?),
            vec![
                session::prepared(&f, &id, &f.a),
                session::activated(&id)?,
                EventBody::CredentialIssued {
                    credential,
                    session: id.clone(),
                    purpose: "session".into(),
                    secret_sha256: Sha256::digest(token.expose()).into(),
                    expires_at_us: now + 300_000_000,
                    activation_deadline_us: now + 60_000_000,
                    expected: Expected::Absent,
                },
                EventBody::CredentialActivated {
                    credential,
                    session: id,
                    expected: revision(1)?,
                    first_request: session::record()?,
                },
            ],
        )?,
        &*lease,
    )?;
    direct.close()?;
    drop(lease);
    let engine = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(3)
        .build()?;
    engine.block_on(async {
        let mut host=HostedRuntime::prepare(initialized,start(&f)?,engine.handle().clone(),&deadline()?).await?;
        let context=host.execution_context();
        let ticket=context.atlas.records.ticket()?.ok_or("record feed pending")?;
        let mut owner=context.reader.snapshot(f.scoped(Visibility::Owner))?;
        let mut after=None;
        controller.runtime().with_writer(&root,Instant::now()+Duration::from_secs(2),|cache,_| {
            loop {
                let Some(feed)=se_core::atlas_records::feed::next(&mut owner,&f.owner_project(),after.clone())? else {break;};
                se_atlas::records::apply(cache,&feed,Instant::now()+Duration::from_secs(1))?;
                after=Some(feed.through);
            }
            context.atlas.records.mark_current(RecordFeedScope::from(cache.identity()),ticket)?;
            Ok(())
        })?;
        owner.close()?;
        let lower=CodeCursorPosition::new(&index,"changes-range",cursor_digest(&("changes-range",AtlasPrincipal::Human(f.owner.clone())))?,CursorKey {integers:vec![0,u64::from(u32::MAX)],bytes:vec![]},None)?.encode()?;
        let controller=Arc::new(Mutex::new(controller));
        host.install_atlas_read_port(Arc::new(ControllerReadPort {controller:controller.clone()}))?;
        let listener=host.listen(engine.handle().clone(),&deadline()?).await?;
        let endpoint=listener.endpoint().clone();
        let before = context.reader.snapshot(f.scoped(Visibility::Owner))?.info().head;
        let stop=host.local_stop();
        let serving=tokio::spawn(host.serve(listener));
        let project=f.project.clone();
        let root_wire=root.clone();
        let query_endpoint=endpoint.clone();
        let replies=tokio::task::spawn_blocking(move ||->Result<(Vec<se_core::ops::AnyOutput>,Option<se_core::ops::AnyOutput>),String> {
            let mut replies=Vec::new();
            for (name,mut input) in [
                ("atlas.find",serde_json::json!({"query":"alpha","mode":"exact"})),
                ("atlas.refs",serde_json::json!({"target":{"Symbol":{"Name":{"name":"alpha","path":"alpha.rs","container":null}}}})),
                ("atlas.impact",serde_json::json!({"target":{"File":"alpha.rs"},"depth":1})),
                ("atlas.changes",serde_json::json!({"since":{"Cursor":lower}})),
                ("atlas.outline",serde_json::json!({"path":"alpha.rs"})),
                ("atlas.find",serde_json::json!({"query":"gHR2i","kind":"symbol","mode":"broad"})),
                ("atlas.impact",serde_json::json!({"target":{"Symbol":{"Name":{"name":"bootstrap","path":"entry.js","container":null}}},"depth":1})),
                ("atlas.find",serde_json::json!({"query":"atlas_private_native_marker","mode":"exact"})),
            ] {
                input["root"]=serde_json::to_value(&root_wire).map_err(|e|e.to_string())?;
                input["byte_budget"]=16384.into();
                replies.push(exchange(&query_endpoint,project.clone(),name,input).map_err(|e|format!("{name}: {e}"))?);
            }
            let hook=match exchange_as(&query_endpoint,project,"atlas.augment",serde_json::json!({"target":{"Symbol":"alpha"},"root":root_wire}),client::lease::ClientCredential::Session(token)) {
                Ok(output)=>Some(output),
                Err(error) if optional_hint_deadline(error.as_ref())=>None,
                Err(error)=>return Err(format!("atlas.augment: {error}")),
            };
            Ok((replies,hook))
        }).await?;
        let disabled = {
            let mut controller = controller.lock().map_err(|_|"controller poisoned")?;
            let result=controller.close(root.clone(), CloseReason::Disabled, Duration::from_secs(2))?;
            let mut disabled_policy=policy();disabled_policy.enabled=false;
            controller.register(registration.clone(), disabled_policy)?;
            result
        };
        assert!(matches!(disabled, CloseResult::Closed));
        let disabled_project=f.project.clone();
        let disabled_endpoint=endpoint.clone();
        let disabled_reply=tokio::task::spawn_blocking(move || exchange(&disabled_endpoint, disabled_project, "atlas.find", serde_json::json!({"query":"alpha"})).map_err(|e|e.to_string())).await??;
        let se_core::ops::AnyOutput::AtlasFind(disabled_find)=disabled_reply else {return Err("disabled family".into());};
        assert!(matches!(disabled_find.value.answer.data, se_types::Read::Unknown {..}));
        assert!(matches!(disabled_find.value.answer.index.state, IndexState::Disabled));
        let after = context.reader.snapshot(f.scoped(Visibility::Owner))?.info().head;
        stop.request();
        let mut outcome=serving.await?;
        let report=outcome.runtime.drain_storage(&deadline()?).await?;
        assert!(report.writer_joined && report.pending.is_empty());
        outcome.listener.close_transport(&context.blocking,&deadline()?).await?.retire(&context.blocking,&deadline()?).await?;
        if let Some(error)=outcome.failure {return Err(Box::<dyn std::error::Error>::from(error));}
        let (replies,hook)=replies?;
        assert_eq!(replies.len(),8,"every public query must return a successful reply");
        use se_core::ops::AnyOutput;
        let AnyOutput::AtlasFind(found)=&replies[0] else {return Err("find family".into());};
        assert!(!present(found.value.answer.data.clone())?.page.items().is_empty());
        let AnyOutput::AtlasRefs(refs)=&replies[1] else {return Err("refs family".into());};
        assert!(!present(refs.value.answer.data.clone())?.items().is_empty());
        let AnyOutput::AtlasImpact(impact)=&replies[2] else {return Err("impact family".into());};
        assert!(!present(impact.value.answer.data.clone())?.dependents.is_empty());
        let AnyOutput::AtlasChanges(changes)=&replies[3] else {return Err("changes family".into());};
        assert!(present(changes.value.answer.data.clone())?.items().is_empty(), "first cold index must establish a baseline without inventing edits");
        let AnyOutput::AtlasOutline(outline)=&replies[4] else {return Err("outline family".into());};
        let outline=present(outline.value.answer.data.clone())?;
        assert!(!outline.symbols.is_empty());assert!(!outline.records.is_empty());
        let AnyOutput::AtlasFind(acronym)=&replies[5] else {return Err("acronym family".into());};
        assert!(present(acronym.value.answer.data.clone())?.page.items().iter().any(|hit|matches!(&hit.target,HitTarget::Code(code) if code.name=="getHTTPResponse2_id")));
        let AnyOutput::AtlasImpact(top_level)=&replies[6] else {return Err("top-level impact family".into());};
        assert!(present(top_level.value.answer.data.clone())?.dependents.iter().any(|d|d.symbol.is_none() && d.file_hops.iter().any(|h|h.from==h.to && h.site.path.as_str()=="entry.js" && h.site.span.is_some())));
        let AnyOutput::AtlasFind(private)=&replies[7] else {return Err("private find family".into());};
        assert!(present(private.value.answer.data.clone())?.page.items().is_empty(), "cold worker indexed a built-in secret path");
        if let Some(hook)=hook {
            let AnyOutput::AtlasAugment(hook)=hook else {return Err("hook family".into());};
            if !hook.value.stdout.is_empty() {
                assert!(matches!(found.value.answer.index.state,IndexState::Current),"uncertain cold index supplied hook context");
                assert!(hook.value.stdout.contains("definition alpha alpha.rs:1"));
                let hint:serde_json::Value=serde_json::from_str(&hook.value.stdout)?;
                assert_eq!(hint["hookSpecificOutput"]["hookEventName"],"PreToolUse");
            }
            assert!(hook.value.stdout.len()<=600);
        }
        assert_eq!(before,after,"query route wrote core history");
        controller.lock().map_err(|_|"controller poisoned")?.close(root,CloseReason::HostDrain,Duration::from_secs(2))?;
        Ok::<(),Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
