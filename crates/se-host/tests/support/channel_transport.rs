//! A provider fixture retains updates until a later committed offset acknowledges
//! them. A lost response can still mean delivery; no synthetic success is implied.
use se_host::channels::*;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, AtomicI64, Ordering},
};
pub struct Sent {
    pub chat: i64,
    pub text: String,
    pub keyboard: Option<serde_json::Value>,
}
#[derive(Default)]
pub struct Transport {
    rows: Mutex<Vec<Incoming>>,
    pub sent: Mutex<Vec<Sent>>,
    changed: tokio::sync::Notify,
    pub lose_reply: AtomicBool,
    fail_poll: AtomicBool,
    next: AtomicI64,
}
impl Transport {
    pub fn push(&self, update: i64, text: String) -> Result<(), ChannelError> {
        self.rows
            .lock()
            .map_err(|_| ChannelError::ReceiverNotRunning)?
            .push(Incoming {
                update: update.into(),
                cursor: ReceiveCursor::new(update.to_string())
                    .map_err(|_| ChannelError::InvalidInput)?,
                content: IncomingContent::Text {
                    phone: PhoneIdentity {
                        subject: 42.into(),
                        private_chat: 42.into(),
                        display_name: "Fixture phone".into(),
                        username: None,
                    },
                    text,
                },
            });
        self.changed.notify_waiters();
        Ok(())
    }
    pub fn interrupt(&self) {
        self.fail_poll.store(true, Ordering::Release);
        self.changed.notify_waiters();
    }
    pub fn unsupported(&self, update: i64) -> Result<(), ChannelError> {
        self.rows
            .lock()
            .map_err(|_| ChannelError::ReceiverNotRunning)?
            .push(Incoming {
                update: update.into(),
                cursor: ReceiveCursor::new(update.to_string())
                    .map_err(|_| ChannelError::InvalidInput)?,
                content: IncomingContent::Unsupported,
            });
        self.changed.notify_waiters();
        Ok(())
    }
    pub fn replies(&self) -> Result<Vec<String>, ChannelError> {
        Ok(self
            .sent
            .lock()
            .map_err(|_| ChannelError::ReceiverNotRunning)?
            .iter()
            .filter(|row| row.text.starts_with("Reply to "))
            .map(|row| row.text.clone())
            .collect())
    }
}
impl ChannelTransport for Transport {
    fn descriptor(&self) -> ConnectorDescriptor {
        Telegram::new().expect("fixture client").descriptor()
    }
    fn receiver(
        self: std::sync::Arc<Self>,
        cursor: Option<ReceiveCursor>,
    ) -> ChannelResult<Box<dyn ChannelReceiver>> {
        receiver(self, cursor)
    }
    fn pairing_link(&self, bot: &BotIdentity, challenge: &str) -> ChannelResult<se_types::Secret> {
        se_types::Secret::new(
            format!("https://t.me/{}?start={challenge}", bot.username).into_bytes(),
        )
        .map_err(|_| ChannelError::InvalidInput)
    }

    fn identity<'a>(&'a self, _: &'a se_types::Secret) -> TransportFuture<'a, BotIdentity> {
        Box::pin(async {
            Ok(BotIdentity {
                id: 23.into(),
                username: "fixture_bot".into(),
                display_name: "Fixture bot".into(),
            })
        })
    }

    fn answer_callback<'a>(
        &'a self,
        _: &'a se_types::Secret,
        _: &'a str,
        _: bool,
    ) -> TransportFuture<'a, ()> {
        Box::pin(async { Ok(()) })
    }
    fn send<'a>(
        &'a self,
        _: &'a se_types::Secret,
        chat: &'a ExternalId,
        text: &'a str,
        buttons: &'a [ActionButton],
    ) -> TransportFuture<'a, ExternalId> {
        Box::pin(async move {
            self.sent
                .lock()
                .map_err(|_| ChannelError::ReceiverNotRunning)?
                .push(Sent {
                    chat: chat.as_str().parse().map_err(|_| ChannelError::InvalidInput)?,
                    text: text.into(),
                    keyboard: (!buttons.is_empty()).then(|| serde_json::json!({"inline_keyboard": buttons.iter().map(|b| vec![serde_json::json!({"text":b.label,"callback_data":b.data})]).collect::<Vec<_>>()})),
                });
            if text.starts_with("Reply to ") && self.lose_reply.swap(false, Ordering::AcqRel) {
                return Err(ChannelError::SendOutcomeUnknown);
            }
            Ok((self.next.fetch_add(1, Ordering::Relaxed) + 1).into())
        })
    }
}

impl FixturePoll for Transport {
    fn poll<'a>(
        &'a self,
        _: &'a se_types::Secret,
        offset: Option<i64>,
    ) -> TransportFuture<'a, Vec<Incoming>> {
        Box::pin(async move {
            loop {
                let changed = self.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if self.fail_poll.swap(false, Ordering::AcqRel) {
                    return Err(ChannelError::RateLimited {
                        retry_after_seconds: 1,
                    });
                }
                {
                    let mut rows = self
                        .rows
                        .lock()
                        .map_err(|_| ChannelError::ReceiverNotRunning)?;
                    if let Some(offset) = offset {
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
                tokio::select! {_=&mut changed=>{},_=tokio::time::sleep(std::time::Duration::from_secs(25))=>return Ok(vec![])}
            }
        })
    }
}

/// The fixture keeps its old provider poll protocol behind the new durable ACK seam.
pub trait FixturePoll: Send + Sync {
    fn poll<'a>(
        &'a self,
        token: &'a se_types::Secret,
        offset: Option<i64>,
    ) -> TransportFuture<'a, Vec<Incoming>>;
}
pub fn receiver<T: FixturePoll + 'static>(
    provider: std::sync::Arc<T>,
    cursor: Option<ReceiveCursor>,
) -> ChannelResult<Box<dyn ChannelReceiver>> {
    let offset = cursor
        .map(|c| {
            c.as_str()
                .parse::<i64>()
                .ok()
                .and_then(|n| n.checked_add(1))
                .ok_or(ChannelError::InvalidInput)
        })
        .transpose()?;
    Ok(Box::new(Receiver {
        provider,
        offset,
        ready: Default::default(),
        pending: None,
    }))
}
struct Receiver<T> {
    provider: std::sync::Arc<T>,
    offset: Option<i64>,
    ready: std::collections::VecDeque<Incoming>,
    pending: Option<ReceiveCursor>,
}
impl<T: FixturePoll> ChannelReceiver for Receiver<T> {
    fn next<'a>(
        &'a mut self,
        token: &'a se_types::Secret,
    ) -> TransportFuture<'a, Option<Incoming>> {
        Box::pin(async move {
            if self.pending.is_some() {
                return Err(ChannelError::InvalidInput);
            }
            if self.ready.is_empty() {
                self.ready = self.provider.poll(token, self.offset).await?.into();
            }
            let value = self.ready.pop_front();
            self.pending = value.as_ref().map(|v| v.cursor.clone());
            Ok(value)
        })
    }
    fn ack(&mut self, cursor: &ReceiveCursor) -> ChannelResult<()> {
        if self.pending.as_ref() != Some(cursor) {
            return Err(ChannelError::InvalidInput);
        }
        self.offset = Some(
            cursor
                .as_str()
                .parse::<i64>()
                .ok()
                .and_then(|n| n.checked_add(1))
                .ok_or(ChannelError::InvalidInput)?,
        );
        self.pending = None;
        Ok(())
    }
}
