//! Public host + actual MCP mail + durable store, with only Telegram substituted.
//! This is not evidence of a real Telegram phone or stock model's behavior.
#![cfg(all(feature = "listener", any(target_os = "linux", windows)))]
#[path = "support/wave2_host_fixture.rs"]
mod support;
#[path = "support/channel_transport.rs"]
mod transport;
use se_host::{channels::*, *};
use se_store::*;
use se_types::IdempotencyKey;
use serde_json::json;
use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use support::*;
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
async fn wait_for(
    channels: &Channels,
    id: &ChannelId,
    test: impl Fn(&ChannelPage) -> bool,
) -> Result<ChannelPage, Box<dyn std::error::Error>> {
    let deadline = bound()?;
    loop {
        deadline.remaining()?;
        let page = inspect(channels, id).await?;
        if test(&page) {
            return Ok(page);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
fn seed_mail(f: &Fixture) -> Check {
    seed(f)?;
    let (mut writer, lease) = direct(f)?;
    let s = session::session()?;
    let at = now()?;
    let issued = credential(
        &s,
        "http",
        "channel-http-fixture",
        at + 300000000,
        at + 60000000,
    )?;
    let EventBody::CredentialIssued { credential: id, .. } = &issued else {
        return Err("credential kind".into());
    };
    let id = *id;
    writer.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("channel-agent-setup")?),
            vec![
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
                        provider: Provider::Claude,
                        model: None,
                        permission: PermissionProfile::WorkspaceWrite,
                        named_profile: "claude".into(),
                        effort: None,
                    },
                    expected: Expected::Absent,
                },
                session::prepared(f, &s, &f.a),
                issued,
                session::activated(&s)?,
                EventBody::CredentialActivated {
                    credential: id,
                    session: s,
                    expected: revision(1)?,
                    first_request: session::record()?,
                },
            ],
        )?,
        &*lease,
    )?;
    writer.close()?;
    drop(lease);
    Ok(())
}
fn roundtrip(lose_response: bool, long_reply: bool) -> Check {
    let f = Fixture::new()?;
    seed_mail(&f)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let initialized=initialize_host_process()?;
        let mut host=HostedRuntime::prepare(initialized,start(&f)?,rt.handle().clone(),&bound()?).await?;
        configure_private_listener(&mut host)?;
        let provider=Arc::new(transport::Transport::default());
        host.install_channel_transport(provider.clone())?;
        assert!(host.install_channel_transport(Arc::new(transport::Transport::default())).is_err());
        let listener=host.listen(rt.handle().clone(),&bound()?).await?;
        let port=host.http_port().ok_or("HTTP listener absent")?;
        let channels=host.channels()?;
        let vault=NativeChannelCredentials::open(&f.options.state_directory,f.store.clone(),f.owner.clone())?;
        let credential=vault.provision(&mut &b"123456:dummy_invalid_provider_token_123456"[..])?;
        let input=ConnectChannel{ connector: Connector::Telegram,credential,target:ChannelTarget{project:f.project.clone(),agent:f.a.clone(),selection_revision:1},policy:ChannelPolicy::SaveOnly,key:IdempotencyKey::new("fixture-channel-connect")?};
        let connected=channels.connect_channel(input.clone(),&bound()?).await?;
        let replay=channels.connect_channel(input,&bound()?).await?;
        assert_eq!(connected.receipt.events,replay.receipt.events);
        let id=connected.connection.id.clone();
        let uri=std::str::from_utf8(connected.ticket.expose_link())?;
        let challenge=uri.split_once("?start=").ok_or("pairing challenge absent")?.1.to_owned();
        let stop=host.local_stop();
        let client = async {
            let work = async {
                provider.push(1, format!("/start {challenge}"))?;
                let awaiting = wait_for(&channels, &id, |p| matches!(
                    p.connections.first().map(|c| &c.pairing),
                    Some(PairingPresentation::AwaitingApproval { .. })
                )).await?;
                let revision = awaiting.connections.first().ok_or("pairing state absent")?.revision;
                channels.confirm_pairing(ConfirmPairing {
                    connection: id.clone(), expected_pairing_revision: revision,
                    key: IdempotencyKey::new("fixture-pair-confirm")?,
                }, &bound()?).await?;
                provider.push(2, "Please do fixture work and send a linked reply.".into())?;
                let saved = wait_for(&channels, &id, |p| p.receipts.len() == 1).await?;
                let receipt = saved.receipts.first().ok_or("Saved receipt absent")?;
                assert!(receipt.read.is_none() && receipt.replies.is_empty());
                assert!(matches!(receipt.notice, NoticeFact::Pending { .. }));
                let original = receipt.message.clone();
                provider.push(2, "Please do fixture work and send a linked reply.".into())?;
                provider.push(3, "x".repeat(se_store::channel::MAX_TEXT_BYTES + 1))?;
                let rejected = wait_for(&channels, &id, |p| p.recent_rejections.as_ref()
                    .is_some_and(|r| r.items.first().is_some_and(|failure|
                        matches!(failure.delivery, ProviderOutput::Sent { .. })))).await?;
                assert_eq!(rejected.receipts.len(), 1);
                assert_eq!(rejected.recent_rejections.as_ref().and_then(|r| r.items.first())
                    .map(|r| r.reason), Some(se_store::channel::Rejection::TooLarge));
                if !lose_response && !long_reply {
                    provider.interrupt();
                    let outage = wait_for(&channels, &id, |p| p.connections.first()
                        .is_some_and(|c| c.receive_coverage.possible_gap.reason == ReceiveGapReason::ReceiverUnavailable)).await?;
                    assert!(outage.connections[0].receive_coverage.last_successful_poll_at_us.is_some());
                    provider.unsupported(4)?;
                    let recovered = wait_for(&channels, &id, |p| p.connections.first()
                        .is_some_and(|c| matches!(c.health, ConnectionHealth::Connected { .. }))).await?;
                    let coverage = &recovered.connections[0].receive_coverage;
                    assert_eq!(coverage.possible_gap.reason, ReceiveGapReason::ReceiverUnavailable);
                    assert!(coverage.possible_gap.from_us.is_some());
                    assert!(coverage.last_successful_poll_at_us.is_some_and(|last| last >= coverage.possible_gap.through_us));
                }
                let read = rpc(port, "channel-http-fixture", "tools/call", json!({
                    "name": "stateengine_msg_read", "arguments": { "message_id": original }
                })).await?;
                require(read["result"]["isError"] != true, format!("MCP read refused: {read}"))?;
                require(read["result"]["structuredContent"]["message"]["channel_reply"]["active"] == true,
                    format!("trusted phone route absent: {read}"))?;
                let readback = wait_for(&channels, &id, |p| p.receipts.first()
                    .is_some_and(|r| r.read.is_some())).await?;
                assert_eq!(readback.receipts.len(), 1);
                provider.lose_reply.store(lose_response, Ordering::Release);
                let reply_body = if long_reply {
                    format!("not-sent-fixture:{}", "x".repeat(5000))
                } else { "Fixture work completed and independently read back.".into() };
                let reply = rpc(port, "channel-http-fixture", "tools/call", json!({
                    "name": "stateengine_msg_send", "arguments": {
                        "to": f.owner, "body": reply_body, "reply_to": original,
                        "idempotency_key": "fixture-linked-phone-reply"
                    }
                })).await?;
                require(reply["result"]["isError"] != true, format!("MCP reply refused: {reply}"))?;
                let done = wait_for(&channels, &id, |p| p.receipts.first()
                    .and_then(|r| r.replies.first()).is_some_and(|r| {
                        if long_reply {
                            matches!(&r.delivery, ProviderOutput::Failed { code } if code == "message_too_large")
                        } else if lose_response { matches!(r.delivery, ProviderOutput::Unknown { .. }) }
                        else { matches!(r.delivery, ProviderOutput::Sent { .. }) }
                    })).await?;
                let receipt = done.receipts.first().ok_or("completed receipt absent")?;
                assert!(receipt.read.is_some());
                assert_eq!(receipt.replies.len(), 1);
                assert_eq!(provider.replies()?.len(), if long_reply { 0 } else { 1 });
                let private = provider.sent.lock().map_err(|_| "fixture send record poisoned")?
                    .iter().all(|sent| sent.chat == 42 && sent.keyboard.is_none());
                assert!(private, "Save only sent outside the approved chat or offered a lifecycle action");
                if long_reply {
                    let deadline = bound()?;
                    loop {
                        deadline.remaining()?;
                        let observed = provider.sent.lock().map_err(|_| "fixture send record poisoned")?
                            .iter().any(|sent| sent.text.contains("could not be sent"));
                        if observed { break; }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    assert!(provider.sent.lock().map_err(|_| "fixture send record poisoned")?
                        .iter().all(|sent| !sent.text.contains("not-sent-fixture:")));
                }
                if lose_response {
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    assert_eq!(provider.replies()?.len(), 1);
                }
                let snapshot = done.connections.first().ok_or("current channel absent")?;
                let disconnected = channels.disconnect(ChannelControl {
                    connection: id.clone(), expected_revision: snapshot.revision,
                    key: IdempotencyKey::new("fixture-disconnect")?,
                }, &bound()?).await?;
                assert!(matches!(disconnected.credential_removal, CredentialRemoval::Removed));
                assert!(vault.catalog()?.credentials.is_empty());
                let revoked = inspect(&channels, &id).await?;
                assert!(matches!(revoked.connections.first().map(|c| &c.pairing),
                    Some(PairingPresentation::Revoked { .. })));
                assert_eq!(revoked.receipts.len(), 1);
                Ok::<_, Box<dyn std::error::Error>>(())
            }.await;
            stop.request();
            work
        };
        let(exit,result)=join(host.serve(listener),client).await;
        let report=exit.finish(&bound()?).await;
        assert!(report.transport_closed && report.endpoint_retired);result
    })
}
/// Protects: 49 — keep Saved, actual MCP Read, linked reply and token removal independently witnessed.
#[test]
fn fixture_phone_saves_actual_mcp_reads_replies_and_disconnect_forgets() -> Check {
    roundtrip(false, false)
}
/// Protects: 49 — retain uncertain provider delivery without sending a duplicate private reply.
#[test]
fn provider_acceptance_with_lost_response_stays_unknown_and_is_not_resent() -> Check {
    roundtrip(true, false)
}

/// Protects: 49 — preserve a long local reply and report its transport refusal without truncation.
#[test]
fn oversized_linked_reply_is_kept_local_and_phone_gets_explicit_send_failure() -> Check {
    roundtrip(false, true)
}
