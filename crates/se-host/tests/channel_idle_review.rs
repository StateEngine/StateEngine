//! Native host/store receiver checks; only the external phone transport is substituted.
#![cfg(all(feature = "listener", any(target_os = "linux", windows)))]
#[path = "support/wave2_host_fixture.rs"]
mod support;
#[path = "support/channel_transport.rs"]
#[allow(
    dead_code,
    reason = "This receiver consumer needs only a subset of the provider fixture."
)]
mod transport;
use se_host::{channels::*, *};
use se_store::*;
use se_types::{IdempotencyKey, Secret};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::Duration,
};
use support::*;

#[derive(Default)]
struct Provider {
    wire: transport::Transport,
    polled: Mutex<HashSet<Vec<u8>>>,
}
impl ChannelTransport for Provider {
    fn descriptor(&self) -> ConnectorDescriptor {
        self.wire.descriptor()
    }
    fn receiver(
        self: std::sync::Arc<Self>,
        cursor: Option<ReceiveCursor>,
    ) -> ChannelResult<Box<dyn ChannelReceiver>> {
        transport::receiver(self, cursor)
    }
    fn pairing_link(&self, bot: &BotIdentity, challenge: &str) -> ChannelResult<se_types::Secret> {
        self.wire.pairing_link(bot, challenge)
    }

    fn identity<'a>(&'a self, token: &'a Secret) -> TransportFuture<'a, BotIdentity> {
        self.wire.identity(token)
    }

    fn answer_callback<'a>(
        &'a self,
        token: &'a Secret,
        id: &'a str,
        accepted: bool,
    ) -> TransportFuture<'a, ()> {
        self.wire.answer_callback(token, id, accepted)
    }
    fn send<'a>(
        &'a self,
        token: &'a Secret,
        chat: &'a ExternalId,
        text: &'a str,
        buttons: &'a [ActionButton],
    ) -> TransportFuture<'a, ExternalId> {
        self.wire.send(token, chat, text, buttons)
    }
}
fn key(value: &str) -> Result<IdempotencyKey, Box<dyn std::error::Error>> {
    Ok(IdempotencyKey::new(value)?)
}
async fn page(
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
async fn until(
    channels: &Channels,
    id: &ChannelId,
    matches: impl Fn(&ChannelPage) -> bool,
) -> Result<ChannelPage, Box<dyn std::error::Error>> {
    let limit = tokio::time::Instant::now() + Duration::from_secs(4);
    loop {
        let current = page(channels, id).await?;
        if matches(&current) {
            return Ok(current);
        }
        if tokio::time::Instant::now() >= limit {
            return Err("Receiver did not deliver within four seconds".into());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn empty_receiver_transitions_and_long_idle_do_not_strand_connections_or_mail() -> Check {
    let f = Fixture::new()?;
    seed(&f)?;
    let (mut writer, lease) = direct(&f)?;
    writer.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("idle-receiver-setup")?),
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
                        provider: se_store::Provider::Claude,
                        model: None,
                        permission: PermissionProfile::WorkspaceWrite,
                        named_profile: "claude".into(),
                        effort: None,
                    },
                    expected: Expected::Absent,
                },
            ],
        )?,
        &*lease,
    )?;
    writer.close()?;
    drop(lease);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let mut host = HostedRuntime::prepare(
            initialize_host_process()?, start(&f)?, rt.handle().clone(), &bound()?,
        ).await?;
        configure_private_listener(&mut host)?;
        let provider = Arc::new(Provider::default());
        host.install_channel_transport(provider.clone())?;
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let channels = host.channels()?;
        let stop = host.local_stop();
        let vault = NativeChannelCredentials::open(
            &f.options.state_directory, f.store.clone(), f.owner.clone(),
        )?;
        let client = async {
            let outcome = async {
                // Cross two former periodic scans with no connections before the first refill.
                tokio::time::sleep(Duration::from_secs(11)).await;
                for round in 0..64 {
                    if round > 0 && round % 16 == 0 {
                        tokio::time::sleep(Duration::from_secs(6)).await;
                    }
                    tokio::time::sleep(Duration::from_micros((round % 8) * 175)).await;
                    let token = format!("123456:obviously_fake_receiver_control_{round:032}");
                    let credential = vault.provision(&mut token.as_bytes())?;
                    let connected = channels.connect_channel(
                        ConnectChannel { connector: Connector::Telegram,
                            credential,
                            target: ChannelTarget {
                                project: f.project.clone(), agent: f.a.clone(), selection_revision: 1,
                            },
                            policy: ChannelPolicy::SaveOnly,
                            key: key(&format!("idle-connect-{round}"))?,
                        },
                        &bound()?,
                    ).await?;
                    let id = connected.connection.id.clone();
                    let discovery = tokio::time::Instant::now() + Duration::from_secs(4);
                    loop {
                        if provider.polled.lock().map_err(|_| "poll observations poisoned")?
                            .contains(token.as_bytes()) {
                            break;
                        }
                        if tokio::time::Instant::now() >= discovery {
                            return Err("A newly committed connection was stranded after an empty transition".into());
                        }
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                    if round == 63 {
                        let challenge = std::str::from_utf8(connected.ticket.expose_link())?
                            .split_once("?start=").ok_or("challenge absent")?.1;
                        provider.wire.push(1, format!("/start {challenge}"))?;
                        let waiting = until(&channels, &id, |p| matches!(
                            p.connections.first().map(|c| &c.pairing),
                            Some(PairingPresentation::AwaitingApproval { .. }),
                        )).await?;
                        channels.confirm_pairing(
                            ConfirmPairing {
                                connection: id.clone(),
                                expected_pairing_revision: waiting.connections[0].revision,
                                key: key("idle-pair-confirm")?,
                            },
                            &bound()?,
                        ).await?;
                        provider.wire.push(2, "Message at the first refill".into())?;
                        until(&channels, &id, |p| p.receipts.len() == 1).await?;
                        tokio::time::sleep(Duration::from_secs(11)).await;
                        provider.wire.push(3, "Message after the channel was quiet".into())?;
                        let delivered = until(&channels, &id, |p| p.receipts.len() == 2).await?;
                        assert_ne!(delivered.receipts[0].message, delivered.receipts[1].message);
                    }
                    let current = page(&channels, &id).await?;
                    let disconnected = channels.disconnect(
                        ChannelControl {
                            connection: id,
                            expected_revision: current.connections[0].revision,
                            key: key(&format!("idle-disconnect-{round}"))?,
                        },
                        &bound()?,
                    ).await?;
                    assert!(matches!(disconnected.credential_removal, CredentialRemoval::Removed));
                    // Vary the consumer's scheduling around each real empty transition.
                    tokio::task::yield_now().await;
                }
                assert!(vault.catalog()?.credentials.is_empty());
                Ok::<_, Box<dyn std::error::Error>>(())
            }.await;
            stop.request();
            outcome
        };
        let (exit, result) = join(host.serve(listener), client).await;
        let report = exit.finish(&bound()?).await;
        assert!(report.transport_closed && report.endpoint_retired);
        result
    })
}

impl transport::FixturePoll for Provider {
    fn poll<'a>(
        &'a self,
        token: &'a Secret,
        offset: Option<i64>,
    ) -> TransportFuture<'a, Vec<Incoming>> {
        Box::pin(async move {
            self.polled
                .lock()
                .map_err(|_| ChannelError::ReceiverNotRunning)?
                .insert(token.expose().to_vec());
            transport::FixturePoll::poll(&self.wire, token, offset).await
        })
    }
}
