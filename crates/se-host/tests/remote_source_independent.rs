//! Protects: remote broker reuse cannot bypass current native binding/key protection or revoked source credentials.
#![cfg(all(feature = "remote", any(target_os = "linux", windows)))]
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
    Arc,
    atomic::{AtomicUsize, Ordering},
};
#[path = "support/wave2_host_fixture.rs"]
mod support;
use support::session;
use support::*;
#[cfg(windows)]
#[path = "support/windows_remote_acl.rs"]
mod native_acl;

fn public_read(path: &std::path::Path, enabled: bool) -> Check {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(if enabled { 0o644 } else { 0o600 }),
        )?;
        Ok(())
    }
    #[cfg(windows)]
    native_acl::public_read(path, enabled)
}
struct Target {
    connects: AtomicUsize,
    list_calls: Arc<AtomicUsize>,
}
impl RemoteConnector for Target {
    fn connect(
        &self,
        _: RemoteRoute,
        grant: MachineSession,
        signer: Arc<dyn CredentialSource>,
    ) -> RemoteFuture<'_, Arc<dyn RemoteClient>> {
        Box::pin(async move {
            self.connects.fetch_add(1, Ordering::Relaxed);
            let _credential = signer.credential()?;
            Ok(Arc::new(Reader {
                device: grant,
                calls: self.list_calls.clone(),
            }) as Arc<dyn RemoteClient>)
        })
    }
}
struct Reader {
    device: MachineSession,
    calls: Arc<AtomicUsize>,
}
impl RemoteClient for Reader {
    fn close(&self) -> RemoteFuture<'_, ()> {
        // This typed target fixture owns no socket, stream or background task.
        // The real source host's HTTP transport and writer close independently
        // below; no outbound transport closure is being simulated here.
        Box::pin(async { Ok(()) })
    }
    fn list(
        &self,
        call: RemoteCallContext,
        request: RemoteList,
    ) -> RemoteFuture<'_, RemoteListResult> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let invoked = call.invocation(&self.device, RemoteRequest::List(request))?;
            let source = invoked.source.ok_or_else(|| {
                se_types::SeError::invalid("fixture source", "actual admitted source")
            })?;
            if !self.device.subject.admits_source(Some(&source)) {
                return Err(se_types::SeError::invalid(
                    "fixture source",
                    "matching source machine",
                ));
            }
            serde_json::from_value(json!({"schema":RemoteListResult::SCHEMA,"agents":{"items":[],"window":{"from":null,"to":null,"limit":20,"complete":true,"omitted":{"count":0,"reason":null}},"next":null}})).map_err(|_|se_types::SeError::invalid("fixture page","typed page"))
        })
    }
    fn watch(
        &self,
        _: RemoteCallContext,
        _: RemoteWatch,
    ) -> RemoteFuture<'_, Box<dyn RemoteWatchStream>> {
        Box::pin(async {
            Err(se_types::SeError::invalid(
                "fixture watch",
                "list-only consumer",
            ))
        })
    }
    fn send(&self, _: RemoteCallContext, _: RemoteSend) -> RemoteFuture<'_, RemoteSendResult> {
        Box::pin(async {
            Err(se_types::SeError::invalid(
                "fixture send",
                "list-only consumer",
            ))
        })
    }
}
/// Protects: actual MCP admission and protected aliases remain effective after a source broker caches a connection.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn actual_mcp_source_broker_refuses_loosened_key_and_revoked_credential() -> Check {
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
            targets: vec![RemoteTarget {
                project: f.project.clone(),
                agent: f.b.clone(),
            }],
            verbs: vec![RemoteVerb::List],
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
  let connector=Arc::new(Target {connects:AtomicUsize::new(0),list_calls:Arc::new(AtomicUsize::new(0))});
  let broker=Arc::new(RemoteBroker::from_protected(source_host,connector.clone(),records,BlockingPool::new(rt.handle().clone())));
  runtime.install_remote_broker(broker)?;
  let listener=runtime.listen(rt.handle().clone(),&bound()?).await?;
  let port=runtime.http_port().ok_or("private port absent")?;let stop=runtime.local_stop();let execution=runtime.execution_context();
  let runtime_generation=runtime.generation().get();
  let consumer=async {
   let result:Check=async {
    let params=json!({"name":"stateengine_remote_list","arguments":{"host":"box","request":{"targets":[],"cursor":null,"limit":20,"budget":32768}}});
    for _ in 0..2 {let reply=rpc(port,"source-independent","tools/call",params.clone()).await?;require(reply.pointer("/result/structuredContent/schema").and_then(serde_json::Value::as_str)==Some(RemoteListResult::SCHEMA),format!("native remote list failed: {reply}"))?;}
    require(connector.connects.load(Ordering::Relaxed)==1,"source broker did not reuse its matching connection")?;
    public_read(&path,true)?;
    let loose=rpc(port,"source-independent","tools/call",params.clone()).await?;
    public_read(&path,false)?;
    require(loose.get("error").is_some()||loose.pointer("/result/isError")==Some(&json!(true)),format!("loose key accepted: {loose}"))?;
    let mut revoked=f.batch(f.owner_project(),Some(fixture::request("revoke-source")?),vec![EventBody::CredentialRevoked {credential,expected:revision(2)?,reason:InputText::Inline("independent public consumer revoke".into())}])?;
    revoked.admission.generation=runtime_generation;
    execution.writer.submit(revoked)?.await?;
    let revoked=rpc(port,"source-independent","tools/call",params).await?;
    require(revoked.get("error").is_some()||revoked.pointer("/result/isError")==Some(&json!(true)),format!("revoked source accepted: {revoked}"))?;
    require(connector.connects.load(Ordering::Relaxed)==1,"refused calls reconnected with a fallback key")?;
    require(connector.list_calls.load(Ordering::Relaxed)==2,"a refused source call reached the retained target client")?;
    Ok(())
   }.await;
   stop.request();result
  };
  let (exit,result)=join(runtime.serve(listener),consumer).await;
  let report=exit.finish(&bound()?).await;
  require(report.transport_closed&&report.endpoint_retired,"source transport did not close")?;
  require(matches!(report.storage,Read::Present {ref value} if value.writer_joined),"source writer did not close")?;
  result
 })
}
