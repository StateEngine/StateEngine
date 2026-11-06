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
                update,
                content: IncomingContent::Text {
                    phone: PhoneIdentity {
                        subject: 42,
                        private_chat: 42,
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
                update,
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
    fn identity<'a>(&'a self, _: &'a se_types::Secret) -> TransportFuture<'a, BotIdentity> {
        Box::pin(async {
            Ok(BotIdentity {
                id: 23,
                username: "fixture_bot".into(),
                display_name: "Fixture bot".into(),
            })
        })
    }
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
                        rows.retain(|row| row.update >= offset);
                    }
                    if !rows.is_empty() {
                        return Ok(rows.iter().take(10).cloned().collect());
                    }
                }
                tokio::select! {_=&mut changed=>{},_=tokio::time::sleep(std::time::Duration::from_secs(25))=>return Ok(vec![])}
            }
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
        chat: i64,
        text: &'a str,
        keyboard: Option<serde_json::Value>,
    ) -> TransportFuture<'a, i64> {
        Box::pin(async move {
            self.sent
                .lock()
                .map_err(|_| ChannelError::ReceiverNotRunning)?
                .push(Sent {
                    chat,
                    text: text.into(),
                    keyboard,
                });
            if text.starts_with("Reply to ") && self.lose_reply.swap(false, Ordering::AcqRel) {
                return Err(ChannelError::SendOutcomeUnknown);
            }
            Ok(self.next.fetch_add(1, Ordering::Relaxed) + 1)
        })
    }
}
