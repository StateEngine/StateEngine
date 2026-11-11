//! Real Host/SQLite/MCP consumers with only the external Telegram transport replaced.
//! No real phone, frontend, paid model or provider wake is claimed by this judge.
#![cfg(all(feature = "listener", any(target_os = "linux", windows)))]
#[path = "support/wave2_host_fixture.rs"]
mod support;
#[path = "support/channel_transport.rs"]
#[allow(
    dead_code,
    reason = "This consumer uses the shared fixture's sender only."
)]
mod transport;
use se_host::{channels::*, *};
use se_store::*;
use se_types::{IdempotencyKey, Secret};
use serde_json::json;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicI64, Ordering},
    },
    time::Duration,
};
use support::*;

#[derive(Default)]
struct Provider {
    output: transport::Transport,
    rows: Mutex<Vec<Incoming>>,
    changed: tokio::sync::Notify,
    acknowledged: AtomicI64,
    blocked: AtomicBool,
}
impl Provider {
    fn push(&self, update: i64, subject: i64, chat: i64, text: &str) -> Check {
        self.rows
            .lock()
            .map_err(|_| "provider rows poisoned")?
            .push(Incoming {
                update: update.into(),
                cursor: ReceiveCursor::new(update.to_string())
                    .map_err(|_| ChannelError::InvalidInput)?,
                content: IncomingContent::Text {
                    phone: PhoneIdentity {
                        subject: subject.into(),
                        private_chat: chat.into(),
                        display_name: "Owner".into(),
                        username: None,
                    },
                    text: text.into(),
                },
            });
        self.changed.notify_waiters();
        Ok(())
    }
    async fn handled_through(&self, update: i64) -> Check {
        let limit = bound()?;
        while self.acknowledged.load(Ordering::Acquire) <= update {
            limit.remaining()?;
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        Ok(())
    }
}
impl ChannelTransport for Provider {
    fn descriptor(&self) -> ConnectorDescriptor {
        self.output.descriptor()
    }
    fn receiver(
        self: std::sync::Arc<Self>,
        cursor: Option<ReceiveCursor>,
    ) -> ChannelResult<Box<dyn ChannelReceiver>> {
        transport::receiver(self, cursor)
    }
    fn pairing_link(&self, bot: &BotIdentity, challenge: &str) -> ChannelResult<se_types::Secret> {
        self.output.pairing_link(bot, challenge)
    }

    fn identity<'a>(&'a self, token: &'a Secret) -> TransportFuture<'a, BotIdentity> {
        self.output.identity(token)
    }

    fn answer_callback<'a>(
        &'a self,
        token: &'a Secret,
        id: &'a str,
        accepted: bool,
    ) -> TransportFuture<'a, ()> {
        self.output.answer_callback(token, id, accepted)
    }
    fn send<'a>(
        &'a self,
        token: &'a Secret,
        chat: &'a ExternalId,
        text: &'a str,
        buttons: &'a [ActionButton],
    ) -> TransportFuture<'a, ExternalId> {
        if self.blocked.load(Ordering::Acquire) {
            return Box::pin(async {
                Err(ChannelError::RateLimited {
                    retry_after_seconds: 1,
                })
            });
        }
        self.output.send(token, chat, text, buttons)
    }
}
fn key(text: &str) -> Result<IdempotencyKey, Box<dyn std::error::Error>> {
    Ok(IdempotencyKey::new(text)?)
}
fn setup(f: &Fixture, agent_session: bool) -> Check {
    seed(f)?;
    let (mut writer, lease) = direct(f)?;
    let mut events = vec![
        EventBody::PrincipalRegistered {
            principal: Actor::Human(f.owner.clone()),
            kind: PrincipalKind::Human,
            owner: f.owner.clone(),
            created_by: None,
            name: "Owner".into(),
            role: "owner".into(),
            expected: Expected::Absent,
        },
        EventBody::ProfileSaved {
            agent: f.a.clone(),
            profile: Profile {
                provider: se_store::Provider::Claude,
                model: None,
                permission: PermissionProfile::WorkspaceWrite,
                named_profile: "claude".into(),
                effort: None,
            },
            expected: Expected::Absent,
        },
    ];
    if agent_session {
        let session = session::session()?;
        let at = now()?;
        let issued = credential(
            &session,
            "http",
            "independent-channel-reader",
            at + 300_000_000,
            at + 60_000_000,
        )?;
        let EventBody::CredentialIssued { credential, .. } = &issued else {
            return Err("credential kind".into());
        };
        let credential = *credential;
        events.extend([
            session::prepared(f, &session, &f.a),
            issued,
            session::activated(&session)?,
            EventBody::CredentialActivated {
                credential,
                session,
                expected: revision(1)?,
                first_request: session::record()?,
            },
        ]);
    }
    writer.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("independent-channel-setup")?),
            events,
        )?,
        &*lease,
    )?;
    writer.close()?;
    Ok(())
}
async fn inspect(
    channels: &Channels,
    id: &ChannelId,
) -> Result<ChannelPage, Box<dyn std::error::Error>> {
    Ok(channels
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
async fn state(
    channels: &Channels,
    id: &ChannelId,
    matches: impl Fn(&ChannelPage) -> bool,
) -> Result<ChannelPage, Box<dyn std::error::Error>> {
    let deadline = bound()?;
    loop {
        deadline.remaining()?;
        let page = inspect(channels, id).await?;
        if matches(&page) {
            return Ok(page);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
fn duration_visible(text: &str) -> bool {
    let words: Vec<_> = text.split_whitespace().collect();
    words.windows(2).any(|pair| {
        pair[0].parse::<u64>().is_ok_and(|n| n > 0)
            && (pair[1].starts_with("second") || pair[1].starts_with("minute"))
    }) || words.iter().any(|word| {
        word.trim_matches(|c: char| !c.is_ascii_alphanumeric())
            .strip_suffix('s')
            .is_some_and(|n| n.parse::<u64>().is_ok_and(|n| n > 0))
    })
}
fn run_case(reply_case: bool, delayed_read: Option<bool>) -> Check {
    let f = Fixture::new()?;
    setup(&f, reply_case || delayed_read == Some(true))?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = rt.block_on(async {
        let initialized = initialize_host_process()?;
        let mut host = HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        configure_private_listener(&mut host)?;
        let provider = Arc::new(Provider::default());
        provider.blocked.store(reply_case, Ordering::Release);
        host.install_channel_transport(provider.clone())?;
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let port = host.http_port().ok_or("missing listener")?;
        let channels = host.channels()?;
        let vault = NativeChannelCredentials::open(&f.options.state_directory, f.store.clone(), f.owner.clone())?;
        let credential = vault.provision(&mut &b"123456:dummy_invalid_provider_token_123456"[..])?;
        let connected = channels.connect_channel(ConnectChannel { connector: Connector::Telegram, credential,
            target: ChannelTarget { project: f.project.clone(), agent: f.a.clone(), selection_revision: 1 },
            policy: ChannelPolicy::SaveOnly, key: key("independent-connect")? }, &bound()?).await?;
        let id = connected.connection.id;
        let challenge = std::str::from_utf8(connected.ticket.expose_link())?
            .split_once("?start=").ok_or("missing challenge")?.1.to_owned();
        let stop = host.local_stop();
        let client = async {
            let result = async {
                provider.push(1, 42, 42, "First contact claims to be Owner")?;
                provider.handled_through(1).await?;
                assert!(inspect(&channels, &id).await?.receipts.is_empty(), "first contact saved mail");
                provider.push(2, 42, 42, &format!("/start {challenge}"))?;
                let pending = state(&channels, &id, |p| matches!(p.connections[0].pairing,
                    PairingPresentation::AwaitingApproval { .. })).await?;
                provider.push(3, 42, 42, "A link holder is not yet authorized")?;
                provider.handled_through(3).await?;
                assert!(inspect(&channels, &id).await?.receipts.is_empty(), "link possession granted authority");
                let confirm = ConfirmPairing { connection: id.clone(),
                    expected_pairing_revision: pending.connections[0].revision, key: key("independent-confirm")? };
                let receipt = channels.confirm_pairing(confirm.clone(), &bound()?).await?;
                let replay = channels.confirm_pairing(confirm.clone(), &bound()?).await?;
                assert_eq!(receipt.events, replay.events, "same-key retry created a second confirmation");
                let mut changed = confirm;
                changed.expected_pairing_revision += 1;
                let conflict = channels.confirm_pairing(changed, &bound()?).await.err()
                    .ok_or("changed intent reused a key")?;
                assert!(matches!(conflict.body.detail(), se_types::Detail::IdempotencyKeyReused(_)),
                    "wrong conflict: {conflict}");
                provider.push(4, 43, 43, "Owner")?;
                provider.push(5, 42, 43, "Owner in a different destination")?;
                provider.push(6, 42, 42, "Approved phone work")?;
                provider.handled_through(6).await?;
                let saved = inspect(&channels, &id).await?;
                assert_eq!(saved.receipts.len(), 1, "foreign identity or destination entered inbox");
                assert!(saved.receipts[0].read.is_none() && saved.receipts[0].replies.is_empty());
                assert!(matches!(saved.receipts[0].notice, NoticeFact::Pending { .. }), "save invented a provider wake");
                provider.push(6, 42, 42, "Approved phone work")?;
                tokio::time::sleep(Duration::from_millis(1200)).await;
                assert_eq!(inspect(&channels, &id).await?.receipts.len(), 1, "provider replay duplicated mail");
                let original = saved.receipts[0].message.clone();
                if let Some(read_first) = delayed_read {
                    if read_first {
                        let read = rpc(port, "independent-channel-reader", "tools/call", json!({
                            "name":"stateengine_msg_read", "arguments":{"message_id":original}})).await?;
                        assert_ne!(read["result"]["isError"], true, "{read}");
                    }
                    let before_delay = inspect(&channels, &id).await?;
                    let before_receipt = before_delay.receipts.iter()
                        .find(|receipt| receipt.message == original).ok_or("missing original receipt")?;
                    let read_marker = before_receipt.read.clone();
                    if read_marker.is_some() != read_first || !before_receipt.replies.is_empty() {
                        return Err("unexpected read or reply before delayed phone status".into());
                    }
                    let until = tokio::time::Instant::now() + Duration::from_secs(75);
                    let delayed = loop {
                        let observed = provider.output.sent.lock().map_err(|_| "send log poisoned")?
                            .iter().find(|sent| sent.text.starts_with("Status for "))
                            .map(|sent| sent.text.clone());
                        if let Some(text) = observed { break text; }
                        assert!(tokio::time::Instant::now() < until, "no delayed phone status");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    };
                    let after_delay = inspect(&channels, &id).await?;
                    let after_receipt = after_delay.receipts.iter()
                        .find(|receipt| receipt.message == original).ok_or("missing original receipt after delay")?;
                    if after_receipt.read != read_marker || !after_receipt.replies.is_empty() {
                        return Err("delayed phone status changed the read marker or invented a linked reply".into());
                    }
                    let expected = if read_first { "Read; no reply yet" } else { "Not read yet" };
                    if !delayed.contains(expected) {
                        return Err(format!("missing exact read/no-reply state: {delayed}").into());
                    }
                    if !duration_visible(&delayed) {
                        return Err(format!("missing elapsed time: {delayed}").into());
                    }
                }
                if reply_case {
                    let plain = rpc(port, "independent-channel-reader", "tools/call", json!({
                        "name":"stateengine_msg_send", "arguments":{"to":f.owner,
                        "body":"Unlinked answer stays local", "idempotency_key":"independent-unlinked"}})).await?;
                    assert_ne!(plain["result"]["isError"], true, "{plain}");
                    assert!(inspect(&channels, &id).await?.receipts[0].replies.is_empty(), "unlinked mail was forwarded");
                    let read = rpc(port, "independent-channel-reader", "tools/call", json!({
                        "name":"stateengine_msg_read", "arguments":{"message_id":original}})).await?;
                    let route = &read["result"]["structuredContent"]["message"]["channel_reply"];
                    assert_eq!(route["active"], true, "{read}");
                    assert_eq!(route["reply_to"], original.to_string(), "{read}");
                    assert!(route["instruction"].as_str().is_some_and(|t| t.contains("final turn answer alone stays local")), "{read}");
                    let linked = rpc(port, "independent-channel-reader", "tools/call", json!({
                        "name":"stateengine_msg_send", "arguments":{"to":f.owner,
                        "body":"Private linked answer", "reply_to":original,
                        "idempotency_key":"independent-linked"}})).await?;
                    assert_ne!(linked["result"]["isError"], true, "{linked}");
                    state(&channels, &id, |p| p.receipts[0].replies.len()==1).await?;
                }
                let before = inspect(&channels, &id).await?;
                let revoke = ChannelControl { connection: id.clone(), expected_revision: before.connections[0].revision,
                    key: key("independent-disconnect")? };
                let first = channels.disconnect(revoke.clone(), &bound()?).await?;
                let again = channels.disconnect(revoke, &bound()?).await?;
                assert_eq!(first.receipt.events, again.receipt.events);
                assert!(matches!(again.credential_removal, CredentialRemoval::Removed));
                assert!(vault.catalog()?.credentials.is_empty());
                provider.blocked.store(false, Ordering::Release);
                provider.push(7, 42, 42, "After revocation")?;
                tokio::time::sleep(Duration::from_millis(1200)).await;
                let revoked = inspect(&channels, &id).await?;
                assert!(matches!(revoked.connections[0].pairing, PairingPresentation::Revoked { .. }));
                assert_eq!(revoked.receipts.len(), 1, "revoke admitted another message");
                if reply_case {
                    assert!(provider.output.sent.lock().map_err(|_| "send log poisoned")?.is_empty(), "revoked queued content escaped");
                    let read = rpc(port, "independent-channel-reader", "tools/call", json!({
                        "name":"stateengine_msg_read", "arguments":{"message_id":original}})).await?;
                    assert_eq!(read["result"]["structuredContent"]["message"]["channel_reply"]["active"], false, "{read}");
                }
                Ok::<_, Box<dyn std::error::Error>>(())
            }.await;
            stop.request();
            result
        };
        let (exit, result) = join(host.serve(listener), client).await;
        let report = exit.finish(&bound()?).await;
        assert!(report.transport_closed && report.endpoint_retired);
        result
    });
    assert!(!f.options.state_directory.join("endpoint.json").exists());
    let lease = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(f.options.state_directory.join("runtime.lock"))?;
    lease.try_lock()?;
    result
}
/// Protects: 49 — link possession and sender labels cannot admit mail without exact confirmed scope.
#[test]
fn phone_pairing_scope_and_keyed_retries_are_checked_before_saved_mail() -> Check {
    run_case(false, None)
}
/// Protects: 48/49 — forward linked recipient replies only, and fence queued private output on revoke.
#[test]
fn linked_reply_guidance_and_disconnect_fence_are_visible_at_the_real_mcp_boundary() -> Check {
    run_case(true, None)
}

/// Protects: 49 — the actual not-read phone status includes elapsed time without marking mail read.
#[test]
fn unread_delayed_phone_status_shows_elapsed_time() -> Check {
    run_case(false, Some(false))
}

/// Protects: 49 — the phone distinguishes recipient read from no linked reply after the delay.
#[test]
fn read_without_reply_delayed_phone_status_names_that_state() -> Check {
    run_case(false, Some(true))
}

impl transport::FixturePoll for Provider {
    fn poll<'a>(
        &'a self,
        _: &'a Secret,
        offset: Option<i64>,
    ) -> TransportFuture<'a, Vec<Incoming>> {
        Box::pin(async move {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                {
                    let mut rows = self
                        .rows
                        .lock()
                        .map_err(|_| ChannelError::ProviderUnreachable)?;
                    if let Some(offset) = offset {
                        self.acknowledged.store(offset, Ordering::Release);
                        rows.retain(|row| {
                            row.update
                                .as_str()
                                .parse::<i64>()
                                .is_ok_and(|update| update >= offset)
                        });
                    }
                    if !rows.is_empty() {
                        return Ok(rows.iter().take(10).cloned().collect());
                    }
                }
                tokio::select! {
                    _=&mut changed=>{},
                    _=tokio::time::sleep(Duration::from_secs(1))=>return Ok(vec![]),
                }
            }
        })
    }
}
