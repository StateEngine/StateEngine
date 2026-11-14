//! Public host + actual MCP mail + durable store, with only Telegram substituted.
//! This is not evidence of a real Telegram phone or stock model's behavior.
#![cfg(all(feature = "listener", any(target_os = "linux", windows)))]
#[path = "support/channel_reply_fault.rs"]
mod fault;
#[path = "support/wave2_host_fixture.rs"]
mod support;
#[path = "support/channel_transport.rs"]
mod transport;
use fault::{FaultTransport, Mode};
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
                        harness: None,
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
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn roundtrip(lose_response: bool, long_reply: bool, mode: Mode) -> Check {
    let f = Fixture::new()?;
    seed_mail(&f)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let initialized=initialize_host_process()?;
        let mut host=HostedRuntime::prepare(initialized,start(&f)?,rt.handle().clone(),&bound()?).await?;
        configure_private_listener(&mut host)?;
        let provider=Arc::new(FaultTransport::default());
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
                    format!("Unicode fixture:{}", "🧪abé".repeat(1700))
                } else { "Fixture work completed and independently read back.".into() };
                let full_reply = format!("Reply to {original}:\n{reply_body}");
                if long_reply { provider.arm(full_reply.clone(), mode)?; }
                let gate = if lose_response || mode == Mode::UnknownSecond {
                    Some(provider.gate_first_reply()?)
                } else { None };
                let reply = rpc(port, "channel-http-fixture", "tools/call", json!({
                    "name": "stateengine_msg_send", "arguments": {
                        "to": f.owner, "body": reply_body, "reply_to": original,
                        "idempotency_key": "fixture-linked-phone-reply"
                    }
                })).await?;
                require(reply["result"]["isError"] != true, format!("MCP reply refused: {reply}"))?;
                if let Some(gate) = &gate {
                    tokio::time::timeout(Duration::from_secs(10), gate.entered()).await?;
                    let pending = inspect(&channels, &id).await?;
                    let reply = pending.receipts.first().and_then(|r| r.replies.first())
                        .ok_or("in-flight reply absent")?;
                    assert!(matches!(&reply.delivery, ProviderOutput::Unknown { code }
                        if code == "attempt_awaiting_reconciliation"));
                    assert!(reply.provider_messages.is_empty());
                }
                let done = wait_for(&channels, &id, |p| {
                    // Release only after this snapshot was read: the old predicate
                    // must see the in-flight first send, not a scheduler-dependent result.
                    if let Some(gate) = &gate { gate.release(); }
                    p.receipts.first()
                    .and_then(|r| r.replies.first()).is_some_and(|r| {
                        if long_reply {
                            match mode {
                                Mode::FailedSecond => matches!(&r.delivery, ProviderOutput::Failed { code } if code == "message_too_large"),
                                Mode::UnknownSecond => matches!(&r.delivery, ProviderOutput::Unknown { code } if code == "send_outcome_unknown"),
                                _ => matches!(&r.delivery, ProviderOutput::Sent { .. }),
                            }
                        } else if lose_response { matches!(&r.delivery, ProviderOutput::Unknown { code } if code == "send_outcome_unknown") }
                        else { matches!(r.delivery, ProviderOutput::Sent { .. }) }
                    })
                }).await?;
                if gate.is_some() {
                    // Drain the real provider outcome without replacing the snapshot
                    // selected by the predicate under test.
                    wait_for(&channels, &id, |p| p.receipts.first()
                        .and_then(|r| r.replies.first()).is_some_and(|r|
                            matches!(&r.delivery, ProviderOutput::Unknown { code }
                                if code == "send_outcome_unknown"))).await?;
                }
                let receipt = done.receipts.first().ok_or("completed receipt absent")?;
                assert!(receipt.read.is_some());
                assert_eq!(receipt.replies.len(), 1);
                assert_eq!(provider.replies()?.len(), 1);
                let private = provider.sent.lock().map_err(|_| "fixture send record poisoned")?
                    .iter().all(|sent| sent.chat == 42 && sent.keyboard.is_none());
                assert!(private, "Save only sent outside the approved chat or offered a lifecycle action");
                if long_reply {
                    let (attempts, accepted) = provider.observations()?;
                    assert!(attempts.iter().all(|part| !part.is_empty() && part.encode_utf16().count() <= 4096));
                    let known = receipt.replies[0].provider_messages.len();
                    match mode {
                        Mode::Complete | Mode::RateLimitedSecond => {
                            assert_eq!(accepted.len(), 3);
                            assert_eq!(accepted.concat(), full_reply, "Unicode body changed or was truncated");
                            assert_eq!(known, accepted.len());
                            assert_eq!(attempts.len(), if mode == Mode::Complete { 3 } else { 4 });
                            assert_eq!(attempts.iter().filter(|part| part.starts_with("Reply to ")).count(), 1,
                                "a known accepted first part was resent");
                        }
                        Mode::FailedSecond | Mode::UnknownSecond => {
                            assert_eq!(attempts.len(), 2);
                            assert_eq!(known, 1, "unknown or refused part was claimed as delivered");
                            assert_eq!(accepted.len(), if mode == Mode::FailedSecond { 1 } else { 2 });
                            assert!(full_reply.starts_with(&accepted.concat()));
                            tokio::time::sleep(Duration::from_secs(3)).await;
                            assert_eq!(provider.observations()?.0, attempts, "partial/unknown output was retried");
                        }
                    }
                }
                if lose_response {
                    assert!(matches!(&receipt.replies[0].delivery, ProviderOutput::Unknown { code }
                        if code == "send_outcome_unknown"), "in-flight send was mistaken for terminal uncertainty");
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
    roundtrip(false, false, Mode::Complete)
}
/// Protects: 49 — retain uncertain provider delivery without sending a duplicate private reply.
#[test]
fn provider_acceptance_with_lost_response_stays_unknown_and_is_not_resent() -> Check {
    roundtrip(true, false, Mode::Complete)
}

/// Protects: 49 — forward the complete Unicode reply in bounded, scalar-safe parts.
#[test]
fn unicode_linked_reply_is_chunked_without_truncation_or_duplicate_prefix() -> Check {
    roundtrip(false, true, Mode::Complete)
}

#[test]
fn partial_known_failure_reports_only_the_accepted_part() -> Check {
    roundtrip(false, true, Mode::FailedSecond)
}
#[test]
fn partial_lost_response_keeps_known_parts_and_never_resends_uncertainty() -> Check {
    roundtrip(false, true, Mode::UnknownSecond)
}
#[test]
fn rate_limited_second_part_resumes_without_resending_the_first() -> Check {
    roundtrip(false, true, Mode::RateLimitedSecond)
}
