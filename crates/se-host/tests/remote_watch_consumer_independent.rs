//! Real MCP calls must retain all selected cursors across bounded pages and a disconnected target stream.
#![cfg(all(feature = "remote", target_os = "linux"))]
use se_host::remote::*;
use se_host::remote::{
    auth::VerifiedLocalOwner,
    bindings::{ProtectedBindings, SavedBinding},
    broker::RemoteBroker,
    keys::ProtectedCredential,
};
use se_host::*;
use se_store::*;
use se_types::Read;
use serde_json::json;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::session;
use support::*;
struct Target {
    connects: AtomicUsize,
    opened: Arc<Mutex<Vec<RemoteWatch>>>,
}
impl RemoteConnector for Target {
    fn connect(
        &self,
        _: RemoteRoute,
        device: MachineSession,
        signer: Arc<dyn CredentialSource>,
    ) -> RemoteFuture<'_, Arc<dyn RemoteClient>> {
        Box::pin(async move {
            self.connects.fetch_add(1, Ordering::Relaxed);
            let _ = signer.credential()?;
            Ok(Arc::new(Reader {
                device,
                opened: self.opened.clone(),
            }) as Arc<dyn RemoteClient>)
        })
    }
}
struct Reader {
    device: MachineSession,
    opened: Arc<Mutex<Vec<RemoteWatch>>>,
}
impl RemoteClient for Reader {
    fn close(&self) -> RemoteFuture<'_, ()> {
        Box::pin(async { Ok(()) })
    }
    fn list(&self, _: RemoteCallContext, _: RemoteList) -> RemoteFuture<'_, RemoteListResult> {
        Box::pin(async { Err(se_types::SeError::invalid("fixture", "watch-only target")) })
    }
    fn send(&self, _: RemoteCallContext, _: RemoteSend) -> RemoteFuture<'_, RemoteSendResult> {
        Box::pin(async { Err(se_types::SeError::invalid("fixture", "watch-only target")) })
    }
    fn watch(
        &self,
        call: RemoteCallContext,
        request: RemoteWatch,
    ) -> RemoteFuture<'_, Box<dyn RemoteWatchStream>> {
        Box::pin(async move {
            let invoked = call.invocation(&self.device, RemoteRequest::Watch(request.clone()))?;
            if !self.device.subject.admits_source(invoked.source.as_ref()) {
                return Err(se_types::SeError::invalid(
                    "fixture source",
                    "current authenticated source",
                ));
            }
            let step = if request.cursors.is_empty() { 0 } else { 3 };
            self.opened
                .lock()
                .map_err(|_| se_types::SeError::invalid("fixture", "unpoisoned requests"))?
                .push(request.clone());
            Ok(Box::new(Pages { request, step }) as Box<dyn RemoteWatchStream>)
        })
    }
}
struct Pages {
    request: RemoteWatch,
    step: usize,
}
impl RemoteWatchStream for Pages {
    fn next(&mut self, _: std::time::Duration) -> RemoteFuture<'_, RemoteWatchBatch> {
        Box::pin(async move {
            let entries = match self.step {
                0 => vec![(0, 1)],
                1 => vec![(1, 1)],
                2 => {
                    return Err(se_types::SeError::invalid(
                        "fixture transport",
                        "intentional target disconnect",
                    ));
                }
                3 => vec![(0, 2), (1, 2)],
                _ => vec![],
            };
            self.step += 1;
            let mut records = Vec::new();
            let mut cursors = Vec::new();
            for (target, ordinal) in entries {
                let target = self.request.targets[target].clone();
                let cursor =
                    se_types::Cursor::new(format!("native-page-{}-{ordinal}", target.agent))?;
                records.push(RemoteWatchRecord::Provisional {
                    target: target.clone(),
                    cursor: cursor.clone(),
                    item: RemoteLiveItem {
                        item_id: format!("{}-{ordinal}", target.agent),
                        role: RemoteTurnRole::Assistant,
                        preview: RemotePreview {
                            text: "synthetic observation ".repeat(25),
                            complete: true,
                            omitted_utf8_bytes: se_types::Omission::None,
                        },
                    },
                    observation: None,
                });
                cursors.push(RemoteCursorSet {
                    target,
                    durable: None,
                    live: Some(cursor),
                });
            }
            let batch = RemoteWatchBatch {
                schema: RemoteWatchBatch::SCHEMA.into(),
                body: RemoteWatchBody {
                    observation_clock: None,
                    records,
                    cursors,
                    complete: self.step > 3,
                    omitted_records: se_types::Omission::None,
                    reset_required: false,
                },
            };
            if serde_json::to_vec(&batch)
                .map_err(|_| se_types::SeError::invalid("fixture", "serializable page"))?
                .len()
                > self.request.budget as usize
            {
                return Err(se_types::SeError::invalid("fixture", "bounded page"));
            }
            Ok(batch)
        })
    }
}
/// Protects: the real MCP source broker merges partial cursor sets and resumes all targets after a stream failure.
#[test]
fn mcp_watch_reconnect_retains_every_rendered_target_cursor() -> Check {
    let initialized = initialize_host_process()?;
    let f = Fixture::new()?;
    seed(&f)?;
    let session = session::session()?;
    let credential = session::record()?;
    let at = now()?;
    let (mut direct, lease) = direct(&f)?;
    direct.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("source-credential")?),
            vec![
                session::prepared(&f, &session, &f.a),
                session::activated(&session)?,
                EventBody::CredentialIssued {
                    credential,
                    session: session.clone(),
                    purpose: "http".into(),
                    secret_sha256: {
                        use sha2::{Digest, Sha256};
                        Sha256::digest(b"source-independent").into()
                    },
                    expires_at_us: at + 300_000_000,
                    activation_deadline_us: at + 60_000_000,
                    expected: Expected::Absent,
                },
                EventBody::CredentialActivated {
                    credential,
                    session: session.clone(),
                    expected: revision(1)?,
                    first_request: session::record()?,
                },
            ],
        )?,
        &*lease,
    )?;
    direct.close()?;
    drop(lease);
    let owner = VerifiedLocalOwner::from_native(
        &f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
        &se_core::admission::HumanTerminal::OutsideAgentTree,
    )?;
    let files = Arc::new(se_host::state_files::Files::open(
        &f.options.state_directory,
    )?);
    let records = Arc::new(ProtectedBindings::new(
        files.clone(),
        f.options.state_directory.clone(),
    ));
    let grant = RemoteGrantId::from_parts(1_700_000_000_000, [33; 10])?;
    let path = records.key_path(&grant);
    let key = ProtectedCredential::initialize(&owner, files, path.clone())?;
    let source_host = RemoteHostId(se_types::Sha256::from_bytes([31; 32]));
    let host_id = RemoteHostId(se_types::Sha256::from_bytes([32; 32]));
    let device = MachineSession {
        host: host_id,
        grant,
        device: RemoteDeviceId::from_parts(1_700_000_000_000, [34; 10])?,
        subject: RemoteSubject::Machine { host: source_host },
        scope: RemoteScope {
            targets: vec![
                RemoteTarget {
                    project: f.project.clone(),
                    agent: f.a.clone(),
                },
                RemoteTarget {
                    project: f.project.clone(),
                    agent: f.b.clone(),
                },
            ],
            verbs: vec![RemoteVerb::Watch],
        },
        authority_revision: 1,
        expires_at: se_types::UnixMicros::new((at + 300_000_000) as u64)?,
    };
    records.save(
        &owner,
        SavedBinding {
            connected: true,
            forward: Some(ssh::ForwardConfig {
                destination: "example.org".into(),
                local: "127.0.0.1:443".parse()?,
                remote_port: 443,
                command: "se remote __authorize".into(),
                host: host_id,
            }),
            alias: "box".into(),
            route: "127.0.0.1:443".parse()?,
            paired: device.clone(),
            credential_sha256: CredentialDigest(key.credential_sha256()),
        },
        None,
    )?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()?;
    rt.block_on(async {
  let mut runtime=HostedRuntime::prepare(initialized,start(&f)?,rt.handle().clone(),&bound()?).await?;
  configure_private_listener(&mut runtime)?;
  let opened=Arc::new(Mutex::new(Vec::new()));
  let connector=Arc::new(Target {connects:AtomicUsize::new(0),opened:opened.clone()});
  let broker=Arc::new(RemoteBroker::from_protected(source_host,connector.clone(),records,BlockingPool::new(rt.handle().clone())));
  runtime.install_remote_broker(broker)?;
  let listener=runtime.listen(rt.handle().clone(),&bound()?).await?;
  let port=runtime.http_port().ok_or("private port absent")?;let stop=runtime.local_stop();
  let consumer=async {
   let result:Check=async {
    let mut cursors=json!([]);let mut rendered=Vec::new();
    for page in 0..4 {
     let params=json!({"name":"stateengine_remote_watch","arguments":{"host":"box","request":{"targets":device.scope.targets,"cursors":cursors,"visible":null,"budget":4096},"wait_ms":0}});
     let reply=rpc(port,"source-independent","tools/call",params).await?;
     if page==2 {require(reply.get("error").is_some()||reply.pointer("/result/isError")==Some(&json!(true)),format!("target disconnect reported success: {reply}"))?;continue;}
     let body=reply.pointer("/result/structuredContent").ok_or_else(||format!("no typed watch output: {reply}"))?;
     require(body.get("schema").and_then(serde_json::Value::as_str)==Some(RemoteWatchBatch::SCHEMA),format!("unexpected watch page: {reply}"))?;
     require(serde_json::to_vec(body)?.len()<=4096,"public MCP watch page exceeded selected budget")?;
     let rows=body.get("records").and_then(serde_json::Value::as_array).ok_or("missing public records")?;
     for row in rows {rendered.push(row.pointer("/item/item_id").and_then(serde_json::Value::as_str).ok_or("missing provisional item")?.to_owned());}
     cursors=body.get("cursors").ok_or("missing public cursors")?.clone();
    }
    require(connector.connects.load(Ordering::Relaxed)==1,"MCP watch did not retain its admitted target client")?;
    let requests=opened.lock().map_err(|_|"fixture requests poisoned")?;
    require(requests.len()==2,format!("expected initial stream and one resume, got {}",requests.len()))?;
    require(requests[0].cursors.is_empty(),"initial stream invented a cursor")?;
    require(requests[1].cursors.len()==2,"reconnect forgot a cursor omitted from the last bounded page")?;
    for target in &device.scope.targets {
     let saved=requests[1].cursors.iter().find(|c|&c.target==target).ok_or("missing resumed target")?;
     require(saved.live.as_ref().map(se_types::Cursor::as_str)==Some(format!("native-page-{}-1",target.agent).as_str()),"reconnect advanced beyond a rendered item")?;
    }
    let expected:Vec<_>=[(&device.scope.targets[0],1),(&device.scope.targets[1],1),(&device.scope.targets[0],2),(&device.scope.targets[1],2)].into_iter().map(|(t,n)|format!("{}-{n}",t.agent)).collect();
    require(rendered==expected,format!("lost, duplicated or reordered public observations: {rendered:?}"))?;
    Ok(())
   }.await;
   stop.request();result
  };
  let (exit,result)=join(runtime.serve(listener),consumer).await;
  let report=exit.finish(&bound()?).await;
  require(report.transport_closed&&report.endpoint_retired,"source transport did not close")?;
  require(matches!(report.storage,Read::Present {ref value} if value.writer_joined),"source writer did not join")?;
  result
 })
}
