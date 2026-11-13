//! Public host and real SQLite, with a scripted opaque-coordinate receiver.
//! This witnesses receiver disconnect/reconnect, not a process crash or a real
//! provider connection. No agent is launched and no mail read/reply is requested.
#![cfg(all(feature = "listener", any(target_os = "linux", windows)))]
#[path = "support/wave2_host_fixture.rs"]
mod support;
#[path = "support/channel_transport.rs"]
#[allow(
    dead_code,
    reason = "This consumer forwards sender setup only; its opaque receiver is independent."
)]
mod transport;

use se_host::{channels::*, *};
use se_store::{
    channel::{Change, Disposition, Pairing, SavedUpdate},
    *,
};
use se_types::{IdempotencyKey, Secret};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};
use support::*;

const PAIR_UPDATE: &str = "pairing:opaque/update";
const MAIL_UPDATE: &str = "mail:opaque/same-update";
// Deliberately neither numeric nor lexicographically monotonic.
const PAIR_CURSOR: &str = "checkpoint:zebra/paired";
const SAVE_CURSOR: &str = "checkpoint:alpha/saved";
const REPLAY_CURSOR: &str = "checkpoint:middle/replayed";
const BODY: &str = "Save this exact opaque-update input once.";

enum Step {
    Deliver { input: Incoming, fail_ack: bool },
    FailBeforeDelivery(Incoming),
}
#[derive(Default)]
struct Observations {
    connection: Option<ChannelId>,
    steps: VecDeque<Step>,
    starts: Vec<Option<ReceiveCursor>>,
    acks: Vec<(ReceiveCursor, bool)>,
    failed_before_delivery: bool,
    original: Option<SavedUpdate>,
    failures: Vec<String>,
}
struct OpaqueTransport {
    delegate: Arc<transport::Transport>,
    options: StoreOptions,
    scope: ReadScope,
    observed: Mutex<Observations>,
    changed: tokio::sync::Notify,
}
impl OpaqueTransport {
    fn new(f: &Fixture) -> Self {
        Self {
            delegate: Arc::new(transport::Transport::default()),
            options: f.options.clone(),
            scope: f.scoped(Visibility::Owner),
            observed: Mutex::new(Observations::default()),
            changed: tokio::sync::Notify::new(),
        }
    }
    fn lock(&self) -> ChannelResult<std::sync::MutexGuard<'_, Observations>> {
        self.observed
            .lock()
            .map_err(|_| ChannelError::ReceiverNotRunning)
    }
    fn checked(&self, result: Check) -> ChannelResult<()> {
        if let Err(error) = result {
            self.lock()?.failures.push(error.to_string());
            return Err(ChannelError::InvalidInput);
        }
        Ok(())
    }
    fn enqueue(&self, step: Step) -> Check {
        self.lock()?.steps.push_back(step);
        self.changed.notify_one();
        Ok(())
    }
    fn connection(&self) -> Result<ChannelId, Box<dyn std::error::Error>> {
        self.lock()?
            .connection
            .clone()
            .ok_or_else(|| "connection absent".into())
    }
    fn before_delivery(&self, input: &Incoming) -> Check {
        // This independent reader is opened before the transport returns failure;
        // the retained input has not been handed to the host at this boundary.
        let reader = present(SqliteFactory::open_reader(&self.options)?)?;
        let mut snapshot = reader.snapshot(self.scope.clone())?;
        let id = self.connection()?;
        require(input.update.as_str() == MAIL_UPDATE, "wrong retained input")?;
        require(
            !snapshot.channel_update_handled(&id, &input.update)?,
            "input disposition existed before delivery",
        )?;
        require(
            snapshot
                .channel_cursor(&id)?
                .as_ref()
                .map(ReceiveCursor::as_str)
                == Some(PAIR_CURSOR),
            "failed receive changed the durable checkpoint",
        )?;
        let saved = snapshot.channel_saved(&id, 0)?;
        require(
            saved.items.is_empty() && saved.omitted == 0,
            "failed receive fabricated a saved receipt",
        )?;
        require(
            snapshot.message_count(query(None, false))? == 0,
            "failed receive fabricated ordinary mail",
        )?;
        self.lock()?.failed_before_delivery = true;
        Ok(())
    }
    #[expect(
        clippy::too_many_lines,
        reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
    )]
    fn before_ack(&self, input: &Incoming) -> Check {
        // Never inspect the host's reader or a fixture writer: ACK must see the
        // commit through a separately opened public SQLite control connection.
        let reader = present(SqliteFactory::open_reader(&self.options)?)?;
        let mut snapshot = reader.snapshot(self.scope.clone())?;
        let id = self.connection()?;
        require(
            snapshot.channel_cursor(&id)? == Some(input.cursor.clone()),
            format!("ACK preceded checkpoint commit for {}", input.cursor),
        )?;
        require(
            snapshot.channel_update_handled(&id, &input.update)?,
            "ACK preceded durable update disposition",
        )?;
        let saved = snapshot.channel_saved(&id, 0)?;
        require(saved.omitted == 0, "saved receipt read was incomplete")?;
        if input.update.as_str() == PAIR_UPDATE {
            require(saved.items.is_empty(), "pairing fabricated saved mail")?;
            let state = present(snapshot.channel_connection(&id)?)?;
            require(
                matches!(state.pairing, Pairing::AwaitingApproval { .. }),
                "pairing disposition was not committed before ACK",
            )?;
            require(
                snapshot.message_count(query(None, false))? == 0,
                "pairing fabricated ordinary mail",
            )?;
            return Ok(());
        }
        require(
            input.update.as_str() == MAIL_UPDATE,
            "unexpected ACK update",
        )?;
        require(
            saved.items.len() == 1,
            "replay duplicated or lost the saved receipt",
        )?;
        let row = &saved.items[0];
        let event = present(snapshot.event(row.event.clone())?)?;
        let EventBody::ChannelRecorded {
            change:
                Change::UpdateHandled {
                    connection,
                    update,
                    cursor,
                    disposition:
                        Disposition::Saved {
                            receipt,
                            message,
                            subject,
                            private_chat,
                        },
                    ..
                },
        } = event.body
        else {
            return Err("saved receipt has no committed Saved disposition".into());
        };
        require(
            connection == id
                && update == input.update
                && cursor.as_ref().map(ReceiveCursor::as_str) == Some(SAVE_CURSOR)
                && receipt == row.receipt
                && message == row.message
                && subject.as_str() == "42"
                && private_chat.as_str() == "42",
            "Saved disposition does not identify the exact original input",
        )?;
        require(
            snapshot.message_count(query(None, false))? == 1,
            "replay duplicated or lost ordinary mail",
        )?;
        let mail = present(snapshot.message(row.message.clone())?)?;
        require(
            mail.sender == self.scope.admission.actor,
            "saved mail is not from the approved Owner",
        )?;
        let state = present(snapshot.channel_connection(&id)?)?;
        require(
            mail.recipient == Actor::Agent(state.target.agent)
                && matches!(mail.body, StoredText::Present(ref body) if body == BODY)
                && mail.body_complete,
            "saved mail recipient or body changed",
        )?;
        require(
            mail.read.is_none() && mail.reply_to.is_none(),
            "receiver fabricated a mail read or reply",
        )?;
        let replies = snapshot.channel_replies(&id, &row.message)?;
        require(
            replies.items.is_empty() && replies.omitted == 0,
            "receiver fabricated linked reply output",
        )?;
        let mut observed = self.lock()?;
        if let Some(original) = &observed.original {
            require(
                row.receipt == original.receipt
                    && row.message == original.message
                    && row.event == original.event
                    && row.ordinal == original.ordinal,
                "replay replaced the original saved receipt/mail",
            )?;
        } else {
            require(
                input.cursor.as_str() == SAVE_CURSOR,
                "first Saved ACK used the replay cursor",
            )?;
            observed.original = Some(row.clone());
        }
        Ok(())
    }
    fn receiver_started(&self, cursor: Option<ReceiveCursor>) -> Check {
        let mut observed = self.lock()?;
        let expected = match observed.starts.len() {
            0 => None,
            1 => {
                require(
                    observed.failed_before_delivery,
                    "reconnected before the pre-delivery failure witness",
                )?;
                Some(PAIR_CURSOR)
            }
            2 => {
                require(
                    observed.original.is_some()
                        && observed
                            .acks
                            .last()
                            .is_some_and(|(c, failed)| c.as_str() == SAVE_CURSOR && *failed),
                    "reconnected without the committed-save ACK failure",
                )?;
                Some(SAVE_CURSOR)
            }
            _ => return Err("unexpected extra receiver reconnect".into()),
        };
        require(
            cursor.as_ref().map(ReceiveCursor::as_str) == expected,
            format!("receiver did not start from durable cursor {expected:?}"),
        )?;
        observed.starts.push(cursor);
        Ok(())
    }
    async fn wait_for(&self, predicate: impl Fn(&Observations) -> bool) -> Check {
        let deadline = bound()?;
        loop {
            deadline.remaining()?;
            {
                let observed = self.lock()?;
                require(
                    observed.failures.is_empty(),
                    format!("receiver witness failed: {:?}", observed.failures),
                )?;
                if predicate(&observed) {
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}
impl ChannelTransport for OpaqueTransport {
    fn descriptor(&self) -> ConnectorDescriptor {
        self.delegate.descriptor()
    }
    fn identity<'a>(&'a self, token: &'a Secret) -> TransportFuture<'a, BotIdentity> {
        self.delegate.identity(token)
    }
    fn receiver(
        self: Arc<Self>,
        cursor: Option<ReceiveCursor>,
    ) -> ChannelResult<Box<dyn ChannelReceiver>> {
        self.checked(self.receiver_started(cursor))?;
        Ok(Box::new(OpaqueReceiver {
            transport: self,
            pending: None,
        }))
    }
    fn pairing_link(&self, bot: &BotIdentity, challenge: &str) -> ChannelResult<Secret> {
        self.delegate.pairing_link(bot, challenge)
    }
    fn answer_callback<'a>(
        &'a self,
        token: &'a Secret,
        id: &'a str,
        accepted: bool,
    ) -> TransportFuture<'a, ()> {
        self.delegate.answer_callback(token, id, accepted)
    }
    fn send<'a>(
        &'a self,
        token: &'a Secret,
        chat: &'a ExternalId,
        text: &'a str,
        buttons: &'a [ActionButton],
    ) -> TransportFuture<'a, ExternalId> {
        self.delegate.send(token, chat, text, buttons)
    }
}
struct OpaqueReceiver {
    transport: Arc<OpaqueTransport>,
    pending: Option<(Incoming, bool)>,
}
impl ChannelReceiver for OpaqueReceiver {
    fn next<'a>(&'a mut self, _: &'a Secret) -> TransportFuture<'a, Option<Incoming>> {
        Box::pin(async move {
            if self.pending.is_some() {
                return Err(ChannelError::InvalidInput);
            }
            loop {
                let changed = self.transport.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                let step = self.transport.lock()?.steps.pop_front();
                match step {
                    Some(Step::FailBeforeDelivery(input)) => {
                        self.transport
                            .checked(self.transport.before_delivery(&input))?;
                        // Retain the same input for the next receiver; the failed
                        // call never delivered it, so it cannot yet be ACKed.
                        self.transport.lock()?.steps.push_front(Step::Deliver {
                            input,
                            fail_ack: true,
                        });
                        return Err(ChannelError::ProviderUnreachable);
                    }
                    Some(Step::Deliver { input, fail_ack }) => {
                        self.pending = Some((input.clone(), fail_ack));
                        return Ok(Some(input));
                    }
                    None => changed.await,
                }
            }
        })
    }
    fn ack(&mut self, cursor: &ReceiveCursor) -> ChannelResult<()> {
        let (input, fail_ack) = self.pending.take().ok_or(ChannelError::InvalidInput)?;
        if &input.cursor != cursor {
            return Err(ChannelError::InvalidInput);
        }
        self.transport.checked(self.transport.before_ack(&input))?;
        self.transport.lock()?.acks.push((cursor.clone(), fail_ack));
        if fail_ack {
            // ACK failure leaves provider delivery uncertain. Replay the exact
            // update/body at a NEW opaque cursor after the host reconnects.
            let mut replay = input;
            replay.cursor =
                ReceiveCursor::new(REPLAY_CURSOR.into()).map_err(|_| ChannelError::InvalidInput)?;
            self.transport.lock()?.steps.push_front(Step::Deliver {
                input: replay,
                fail_ack: false,
            });
            return Err(ChannelError::ProviderUnreachable);
        }
        Ok(())
    }
}
fn incoming(
    update: &str,
    cursor: &str,
    text: String,
) -> Result<Incoming, Box<dyn std::error::Error>> {
    Ok(Incoming {
        update: ExternalId::new(update.into())?,
        cursor: ReceiveCursor::new(cursor.into())?,
        content: IncomingContent::Text {
            phone: PhoneIdentity {
                subject: 42.into(),
                private_chat: 42.into(),
                display_name: "Fixture phone".into(),
                username: None,
            },
            text,
        },
    })
}
fn seed_selection(f: &Fixture) -> Check {
    seed(f)?;
    let (mut writer, lease) = direct(f)?;
    writer.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request("opaque-checkpoint-selection")?),
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
            ],
        )?,
        &*lease,
    )?;
    writer.close()?;
    drop(lease);
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

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn receiver_reconnect_commits_opaque_replay_checkpoint_before_ack_without_duplicate_mail() -> Check
{
    let f = Fixture::new()?;
    seed_selection(&f)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let initialized = initialize_host_process()?;
        let mut host =
            HostedRuntime::prepare(initialized, start(&f)?, rt.handle().clone(), &bound()?).await?;
        configure_private_listener(&mut host)?;
        let provider = Arc::new(OpaqueTransport::new(&f));
        host.install_channel_transport(provider.clone())?;
        let listener = host.listen(rt.handle().clone(), &bound()?).await?;
        let channels = host.channels()?;
        let vault = NativeChannelCredentials::open(
            &f.options.state_directory,
            f.store.clone(),
            f.owner.clone(),
        )?;
        let credential =
            vault.provision(&mut &b"123456:dummy_invalid_provider_token_123456"[..])?;
        let connected = channels
            .connect_channel(
                ConnectChannel {
                    connector: Connector::Telegram,
                    credential,
                    target: ChannelTarget {
                        project: f.project.clone(),
                        agent: f.a.clone(),
                        selection_revision: 1,
                    },
                    policy: ChannelPolicy::SaveOnly,
                    key: IdempotencyKey::new("opaque-checkpoint-connect")?,
                },
                &bound()?,
            )
            .await?;
        let id = connected.connection.id.clone();
        provider.lock()?.connection = Some(id.clone());
        let link = std::str::from_utf8(connected.ticket.expose_link())?;
        let challenge = link
            .split_once("?start=")
            .ok_or("pairing challenge absent")?
            .1;
        let stop = host.local_stop();
        let client = async {
            let work = async {
                provider.enqueue(Step::Deliver {
                    input: incoming(PAIR_UPDATE, PAIR_CURSOR, format!("/start {challenge}"))?,
                    fail_ack: false,
                })?;
                provider.wait_for(|o| o.acks.len() == 1).await?;
                let awaiting = inspect(&channels, &id).await?;
                let state = awaiting.connections.first().ok_or("pairing state absent")?;
                require(
                    matches!(state.pairing, PairingPresentation::AwaitingApproval { .. }),
                    "public channel did not expose pairing approval",
                )?;
                channels
                    .confirm_pairing(
                        ConfirmPairing {
                            connection: id.clone(),
                            expected_pairing_revision: state.revision,
                            key: IdempotencyKey::new("opaque-checkpoint-pair")?,
                        },
                        &bound()?,
                    )
                    .await?;
                provider.enqueue(Step::FailBeforeDelivery(incoming(
                    MAIL_UPDATE,
                    SAVE_CURSOR,
                    BODY.into(),
                )?))?;
                provider.wait_for(|o| o.acks.len() == 3).await?;
                {
                    let observed = provider.lock()?;
                    require(
                        observed.failed_before_delivery,
                        "pre-delivery failure not witnessed",
                    )?;
                    require(
                        observed.starts.len() == 3,
                        "both receiver reconnects not witnessed",
                    )?;
                    require(
                        observed
                            .acks
                            .iter()
                            .map(|(cursor, failed)| (cursor.as_str(), *failed))
                            .collect::<Vec<_>>()
                            == vec![
                                (PAIR_CURSOR, false),
                                (SAVE_CURSOR, true),
                                (REPLAY_CURSOR, false),
                            ],
                        "wrong ACK order or ACK failure boundary",
                    )?;
                }
                let page = inspect(&channels, &id).await?;
                require(
                    page.receipts.len() == 1,
                    "public channel duplicated or lost Saved receipt",
                )?;
                let receipt = &page.receipts[0];
                {
                    let observed = provider.lock()?;
                    let original = observed
                        .original
                        .as_ref()
                        .ok_or("original receipt absent")?;
                    require(
                        receipt.id == original.receipt
                            && receipt.message == original.message
                            && receipt.saved.event == original.event,
                        "public receipt changed across replay",
                    )?;
                }
                require(
                    receipt.read.is_none()
                        && receipt.replies.is_empty()
                        && receipt.replies_omitted == 0,
                    "Save only fabricated a public read or linked reply",
                )?;
                require(
                    matches!(receipt.notice, NoticeFact::Pending { .. }),
                    "unlaunched agent was reported to have received the mail",
                )?;
                require(
                    provider.delegate.replies()?.is_empty(),
                    "provider received a fabricated linked reply",
                )?;
                // A final fresh reader witnesses the NEW replay checkpoint, not
                // just the original Saved event's intentionally unchanged cursor.
                provider.before_ack(&incoming(MAIL_UPDATE, REPLAY_CURSOR, BODY.into())?)?;
                Ok::<_, Box<dyn std::error::Error>>(())
            }
            .await;
            stop.request();
            work
        };
        let (exit, result) = join(host.serve(listener), client).await;
        let report = exit.finish(&bound()?).await;
        require(
            report.transport_closed && report.endpoint_retired,
            "public local_stop did not close transport and retire endpoint",
        )?;
        result
    })
}
