//! Independent status facts from the same committed read pin. Listing/inspecting
//! never marks mail read or infers a reply from a provider's final turn text.
mod cursor;
mod receipt;
use super::{service::*, *};
use crate::host::{AsChannelDeadline, ChannelDeadline as Deadline};
use receipt::{output_fact, receipt};
use se_core::store_error::store_error;
use se_store::{
    Snapshot, SqliteSnapshot,
    channel::{Connection, Pairing, SavedUpdate},
};
use se_types::{Read, Result};
use std::{sync::atomic::Ordering, time::Duration};

impl Channels {
    pub async fn inspect(
        &self,
        input: InspectChannels,
        deadline: &impl AsChannelDeadline,
    ) -> Result<ChannelPage> {
        let deadline = &deadline.as_channel_deadline();
        if input.receipt.is_some() && input.connection.is_none() {
            return Err(channel_error(ChannelError::InvalidInput));
        }
        if input.cursor.as_ref().is_some_and(|s| s.len() > 512) {
            return Err(channel_error(ChannelError::InvalidInput));
        }
        let expected = input
            .cursor
            .as_deref()
            .map(|s| self.decode_cursor(s, &input.connection, &input.receipt))
            .transpose()?;
        let until = input
            .wait_until_us
            .unwrap_or(0)
            .min(now()?.saturating_add(25_000_000));
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let (page, current) = self
                .inspect_page(&input, expected.as_ref(), deadline)
                .await?;
            let changed = expected.as_ref().is_none_or(|old| {
                old.head != current.head
                    || old.health != current.health
                    || old.connections != 0
                    || old.mail != 0
            });
            if changed || now()? >= until {
                return Ok(page);
            }
            let wait = Duration::from_micros(until.saturating_sub(now()?).max(0) as u64)
                .min(Duration::from_secs(1))
                .min(deadline.remaining()?);
            // Ordinary mail marks also wake this bounded check without creating
            // a subprocess, scanning history, or adding an acknowledgment.
            tokio::select! {_=&mut notified=>{},_=tokio::time::sleep(wait)=>{}}
        }
    }
    fn health_state(
        &self,
    ) -> Result<(
        std::collections::HashMap<ChannelId, super::coverage::ReceiverObservation>,
        u64,
    )> {
        let health = self
            .health
            .lock()
            .map_err(|_| channel_error(ChannelError::ReceiverNotRunning))?;
        Ok((health.clone(), self.health_version.load(Ordering::Acquire)))
    }
    async fn inspect_page(
        &self,
        input: &InspectChannels,
        expected: Option<&cursor::Cursor>,
        deadline: &Deadline,
    ) -> Result<(ChannelPage, cursor::Cursor)> {
        let at = now()?;
        let (health, health_version) = self.health_state()?;
        let running = self.receiver_running.load(Ordering::Acquire);
        let service_key = self.pairing_key.clone();
        let selected = input.connection.clone();
        let receipt_id = input.receipt.clone();
        let before = expected.map(|v| v.mail).unwrap_or(0);
        let after = expected.map(|v| v.connections).unwrap_or(0);
        let project = match &selected {
            Some(id) => Some(self.connection(id.clone(), deadline).await?.target.project),
            None => None,
        };
        let owner = self.owner.clone();
        let old_incarnation = expected.map(|v| v.incarnation);
        self.read(project, deadline, move |cx| {
            let version = cx.read.channel_version().map_err(|e| store_error(&e))?;
            if old_incarnation.is_some_and(|v| v != version.incarnation) {
                return Err(channel_error(ChannelError::InvalidInput));
            }
            let mut page = ChannelPage {
                connections: vec![],
                receipts: vec![],
                cursor: String::new(),
                watch_cursor: String::new(),
                complete: true,
                omitted: 0,
                recent_rejections: None,
            };
            let mut cursor = cursor::Cursor {
                connections: 0,
                mail: 0,
                incarnation: version.incarnation,
                head: version.head,
                health: health_version,
            };
            let connection = selected_connection(cx.read, &selected)?;
            if let Some(connection) = &connection {
                page.recent_rejections = recent_rejections(cx.read, connection)?;
                page.connections
                    .push(snapshot(connection, at, running, &health));
                let saved = saved_rows(cx.read, connection, &receipt_id, before)?;
                page.omitted = saved.omitted;
                append_saved_receipts(
                    cx.read,
                    &mut page,
                    &mut cursor,
                    connection,
                    saved.items,
                    &receipt_id,
                    at,
                )?;
                if page.omitted == 0 {
                    cursor.mail = 0;
                }
            } else {
                connection_listing(cx.read, after, &mut page, &mut cursor, at, running, &health)?;
            }
            seal_page(
                &mut page,
                &mut cursor,
                &version,
                &service_key,
                &owner,
                &selected,
                &receipt_id,
            )?;
            Ok((page, cursor))
        })
        .await
    }
}
fn snapshot(
    state: &Connection,
    at: i64,
    running: bool,
    health: &std::collections::HashMap<ChannelId, super::coverage::ReceiverObservation>,
) -> ChannelSnapshot {
    let pairing = match &state.pairing {
        Pairing::Challenge { expires_at_us, .. } if *expires_at_us > at => {
            PairingPresentation::Challenge {
                revision: state.revision,
                expires_at_us: *expires_at_us,
            }
        }
        Pairing::AwaitingApproval {
            phone,
            expires_at_us,
        } if *expires_at_us > at => PairingPresentation::AwaitingApproval {
            revision: state.revision,
            phone: phone.clone(),
            expires_at_us: *expires_at_us,
        },
        Pairing::Challenge { expires_at_us, .. }
        | Pairing::AwaitingApproval { expires_at_us, .. } => PairingPresentation::Expired {
            revision: state.revision,
            expired_at_us: *expires_at_us,
        },
        Pairing::Paired { phone } => PairingPresentation::Paired {
            revision: state.revision,
            phone: phone.clone(),
        },
        Pairing::Revoked => PairingPresentation::Revoked {
            revision: state.revision,
        },
    };
    let revoked = matches!(state.pairing, Pairing::Revoked);
    ChannelSnapshot {
        id: state.id.clone(),
        connector: state.connector,
        revision: state.revision,
        target: state.target.clone(),
        bot: state.bot.clone(),
        policy: state.policy.clone(),
        pairing,
        health: if revoked {
            ConnectionHealth::Disconnected
        } else if !running {
            ConnectionHealth::ReceiverNotRunning {
                reason: "receiver_stopped".into(),
            }
        } else {
            health
                .get(&state.id)
                .map(|observation| observation.health.clone())
                .unwrap_or(ConnectionHealth::Unavailable {
                    code: "receiver_starting".into(),
                })
        },
        receive_coverage: {
            let coverage = health
                .get(&state.id)
                .map(|observation| observation.coverage.clone())
                .unwrap_or_else(|| ReceiveCoverage::unobserved(at));
            if running && !revoked {
                coverage
            } else {
                coverage.stopped(at)
            }
        },
        credential_removal: if state.credential_removed {
            CredentialRemoval::Removed
        } else if revoked {
            CredentialRemoval::Pending {
                code: "credential_removal_pending".into(),
            }
        } else {
            CredentialRemoval::Retained
        },
        observed_at_us: at,
    }
}

fn selected_connection(
    read: &mut SqliteSnapshot,
    selected: &Option<ChannelId>,
) -> Result<Option<Connection>> {
    let connection = match selected {
        Some(id) => Some(se_core::scope::require_present(
            read.channel_connection(id).map_err(|e| store_error(&e))?,
            "channel",
            "Inspect the Owner's connections.",
        )?),
        None => None,
    };
    Ok(connection)
}
fn recent_rejections(
    read: &mut SqliteSnapshot,
    connection: &Connection,
) -> Result<Option<RejectionWindow>> {
    let failures = read
        .channel_recent_rejections(&connection.id)
        .map_err(|e| store_error(&e))?;
    let window = RejectionWindow {
        more: failures.more,
        items: failures
            .items
            .into_iter()
            .map(|row| {
                Ok(InputRejection {
                    update: row.update,
                    reason: row.reason,
                    at_us: row.at_us,
                    delivery: output_fact(
                        &row.output_state,
                        row.provider_message,
                        row.output_at_us,
                        row.failure,
                    )?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    };
    Ok(Some(window))
}
fn saved_rows(
    read: &mut SqliteSnapshot,
    connection: &Connection,
    receipt_id: &Option<ReceiptId>,
    before: u64,
) -> Result<se_store::channel::ChannelRows<SavedUpdate>> {
    let rows = if let Some(id) = receipt_id {
        let value = se_core::scope::require_present(
            read.channel_receipt(&connection.id, id)
                .map_err(|e| store_error(&e))?,
            "saved phone receipt",
            "Inspect the original connection and receipt ID.",
        )?;
        se_store::channel::ChannelRows {
            items: vec![value],
            after: 0,
            omitted: 0,
        }
    } else {
        read.channel_saved(&connection.id, before)
            .map_err(|e| store_error(&e))?
    };
    Ok(rows)
}
fn append_saved_receipts(
    read: &mut SqliteSnapshot,
    page: &mut ChannelPage,
    cursor: &mut cursor::Cursor,
    connection: &Connection,
    items: Vec<SavedUpdate>,
    receipt_id: &Option<ReceiptId>,
    at: i64,
) -> Result<()> {
    let total = items.len();
    for (index, saved) in items.into_iter().enumerate() {
        if receipt_id.as_ref().is_some_and(|id| *id != saved.receipt) {
            continue;
        }
        let ordinal = saved.ordinal;
        let receipt = receipt(read, connection, saved, at)?;
        page.receipts.push(receipt);
        if serde_json::to_vec(page)
            .map_err(|_| channel_error(ChannelError::InvalidInput))?
            .len()
            > 250 * 1024
        {
            page.receipts.pop();
            page.omitted = page.omitted.saturating_add((total - index) as u64);
            break;
        }
        cursor.mail = ordinal;
    }
    Ok(())
}
fn connection_listing(
    read: &mut SqliteSnapshot,
    after: u64,
    page: &mut ChannelPage,
    cursor: &mut cursor::Cursor,
    at: i64,
    running: bool,
    health: &std::collections::HashMap<ChannelId, super::coverage::ReceiverObservation>,
) -> Result<()> {
    let rows = read
        .channel_connections(after)
        .map_err(|e| store_error(&e))?;
    page.omitted = rows.omitted;
    cursor.connections = if rows.omitted > 0 { rows.after } else { 0 };
    page.connections = rows
        .items
        .iter()
        .map(|state| snapshot(state, at, running, health))
        .collect();
    Ok(())
}
fn seal_page(
    page: &mut ChannelPage,
    cursor: &mut cursor::Cursor,
    version: &se_store::channel::Version,
    service_key: &se_types::Secret,
    owner: &se_types::HumanId,
    selected: &Option<ChannelId>,
    receipt_id: &Option<ReceiptId>,
) -> Result<()> {
    page.complete = page.omitted == 0 && page.receipts.iter().all(|r| r.replies_omitted == 0);
    page.cursor = cursor::encode(
        service_key,
        &version.store,
        owner,
        selected,
        receipt_id,
        cursor,
    )?;
    let watch = cursor::Cursor {
        connections: 0,
        mail: 0,
        ..cursor.clone()
    };
    page.watch_cursor = cursor::encode(
        service_key,
        &version.store,
        owner,
        selected,
        receipt_id,
        &watch,
    )?;
    if serde_json::to_vec(page)
        .map_err(|_| channel_error(ChannelError::InvalidInput))?
        .len()
        > 256 * 1024
    {
        return Err(channel_error(ChannelError::MessageTooLarge));
    }
    Ok(())
}
