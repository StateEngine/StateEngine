//! One native host consumer joins the real connector to durable mail and output.
use super::*;
use crate::runtime::test_support::fixture as data;
use crate::{
    HostKind, HostLimits, HostStart, HostedRuntime,
    client::{ClientOptions, lease::Deadline},
};
use se_store::{
    Actor, DirectStore, ReadStore, Snapshot, SqliteFactory, StoreFactory, StoredText, Visibility,
    WriterOptions,
};
use se_types::{
    HostEpoch, HostGeneration, IdempotencyKey, MachineId, ProcessFields, ProcessInstance,
};
use std::{
    fs,
    io::Write,
    num::{NonZeroU16, NonZeroU32},
    sync::atomic::AtomicBool,
};

fn positive(n: u32) -> Check<NonZeroU32> {
    NonZeroU32::new(n).ok_or("zero limit".into())
}
fn bound() -> Check<Deadline> {
    Ok(Deadline::from_options(&ClientOptions {
        expected_generation: None,
        timeout: Duration::from_secs(30),
        cancelled: Arc::new(AtomicBool::new(false)),
    })?)
}
fn key(value: &str) -> Check<IdempotencyKey> {
    Ok(IdempotencyKey::new(value.to_owned())?)
}
fn start(f: &data::Fixture) -> Check<HostStart> {
    let machine = MachineId::new("native-channel-review")?;
    let boot = se_proc::current_runtime_identity(machine.clone())
        .map_err(|e| format!("native boot identity: {e:?}"))?
        .boot_id;
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
            maximum_requests: NonZeroU16::new(4).ok_or("zero requests")?,
            queue_requests: NonZeroU16::new(16).ok_or("zero queue")?,
            resident_bytes: positive(1024 * 1024)?,
            group_bytes: positive(1024 * 1024)?,
        },
        limits: HostLimits {
            sessions: positive(2)?,
            active_connections: positive(2)?,
            preauth_connections: positive(2)?,
            parked_mail_waits: positive(2)?,
            resident_queue_bytes: positive(1024 * 1024)?,
            session_notice_ids: positive(16)?,
            aggregate_notice_ids: positive(32)?,
            response_bytes: positive(1024 * 1024)?,
            blocking_jobs: positive(2)?,
        },
    })
}
async fn inspect(service: &Channels, id: &ChannelId) -> Check<ChannelPage> {
    Ok(service
        .inspect(
            InspectChannels {
                connection: Some(id.clone()),
                receipt: None,
                cursor: None,
                wait_until_us: None,
            },
            &bound()?,
        )
        .await?)
}

/// The real Gateway feeds a native host: no mail before approval, one durable
/// Owner message afterwards, and Saved never manufactures read or wake proof.
#[test]
fn discord_wire_review_native_host_saves_only_after_exact_approval() -> Check {
    let initialized = crate::initialize_host_process()?;
    let f = data::Fixture::new()?;
    let (direct, lease) = f.direct()?;
    direct.close()?;
    drop(lease);
    let files = se_proc::NativeStateFiles::open(&f.options.state_directory)?;
    let mut staged = files.create_staging(&f.options.state_directory)?;
    staged.file.write_all(&[23; 32])?;
    staged.file.sync_all()?;
    drop(staged.file);
    files.publish_no_replace(&staged.path, &f.options.state_directory.join("credential"))?;
    let provider = Fixture::new("pairing")?;
    let runtime = runtime()?;
    provider.finish(runtime.block_on(async {
        let mut host = HostedRuntime::prepare(initialized, start(&f)?, runtime.handle().clone(), &bound()?).await?;
        host.install_channel_transport(provider.adapter.clone())?;
        let service = host.channels()?;
        let credentials = NativeChannelCredentials::open(&f.options.state_directory, f.store.clone(), f.owner.clone())?;
        let credential = credentials.provision(&mut provider.token.expose())?;
        let listener = host.listen(runtime.handle().clone(), &bound()?).await?;
        let stop = host.local_stop();
        let consumer = async {
            let result: Check = async {
                let connected = service.connect_channel(ConnectChannel {
                    connector: Connector::Discord, credential,
                    target: ChannelTarget { project: f.project.clone(), agent: f.a.clone(), selection_revision: 1 },
                    policy: ChannelPolicy::SaveOnly, key: key("native-channel-connect")?,
                }, &bound()?).await?;
                let id = connected.connection.id;
                fs::write(provider.root.join("incoming.json"), serde_json::to_vec(&json!({"pairing": connected.ticket.expose_message()}))?)?;
                let expires = std::time::Instant::now() + Duration::from_secs(20);
                let revision = loop {
                    let page = inspect(&service, &id).await?;
                    require(page.receipts.is_empty(), "unapproved sender created saved mail")?;
                    if let Some(PairingPresentation::AwaitingApproval { revision, phone, .. }) = page.connections.first().map(|c| &c.pairing) {
                        require(phone.subject.to_string()=="1001" && phone.private_chat.to_string()=="2001", "approval offered the wrong identity")?;
                        break *revision;
                    }
                    if std::time::Instant::now() > expires { return Err("pairing candidate was not observed".into()); }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                };
                service.confirm_pairing(ConfirmPairing { connection: id.clone(), expected_pairing_revision: revision, key: key("native-channel-approve")? }, &bound()?).await?;
                fs::write(provider.root.join("approved"), "approved")?;
                let receipt = loop {
                    let page = inspect(&service, &id).await?;
                    if let Some(receipt) = page.receipts.first() {
                        require(page.receipts.len()==1, "one provider message became multiple mail rows")?;
                        break receipt.clone();
                    }
                    if std::time::Instant::now() > expires { return Err("approved text did not become saved mail".into()); }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                };
                require(receipt.read.is_none() && matches!(receipt.notice, NoticeFact::Pending { .. }), "Saved claimed recipient read or wake")?;
                let reader = data::present(SqliteFactory::open_reader(&f.options)?)?;
                let mut snapshot = reader.snapshot(f.scoped(Visibility::Owner))?;
                let mail = data::present(snapshot.message(receipt.message.clone())?)?;
                require(mail.sender==Actor::Human(f.owner.clone()) && mail.recipient==Actor::Agent(f.a.clone()), "private input became another actor's mail")?;
                require(matches!(mail.body, StoredText::Present(ref body) if body=="durable-local-work"), "saved mail changed the received body")?;
                snapshot.close()?;
                loop {
                    let sent = provider.events()?.iter().any(|e| e["kind"]=="post" && e["body"]["content"].as_str().is_some_and(|s| s.contains("Saved") && s.contains(&receipt.message.to_string())));
                    if sent { break; }
                    if std::time::Instant::now() > expires { return Err("Saved output did not name its committed mail".into()); }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                provider.no_fixture_errors()
            }.await;
            stop.request(); result
        };
        let (exit, result) = tokio::join!(host.serve(listener), consumer);
        let closure = exit.finish(&bound()?).await;
        result?;
        require(closure.transport_closed && closure.endpoint_retired, "native host did not close its owned transport")
    }))
}
