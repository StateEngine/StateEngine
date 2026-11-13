//! Independent real TLS/Gateway/REST controls. Native Windows/macOS and a live
//! provider account are separate qualifications; this local fixture is Linux-only.
use super::*;
use std::sync::Arc;
mod fixture;
mod host;
use fixture::Fixture;
type Check<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn require(condition: bool, message: &str) -> Check {
    if condition {
        Ok(())
    } else {
        Err(message.to_owned().into())
    }
}
fn runtime() -> Check<tokio::runtime::Runtime> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}
async fn next(receiver: &mut dyn ChannelReceiver, token: &se_types::Secret) -> Check<Incoming> {
    Ok(
        tokio::time::timeout(Duration::from_secs(15), receiver.next(token))
            .await??
            .ok_or("expected dispatch")?,
    )
}
async fn ready(f: &Fixture) -> Check<Box<dyn ChannelReceiver>> {
    let mut receiver = f.adapter.clone().receiver(None)?;
    let first = next(receiver.as_mut(), &f.token).await?;
    require(
        matches!(first.content, IncomingContent::Unsupported),
        "READY became user input",
    )?;
    receiver.ack(&first.cursor)?;
    Ok(receiver)
}

/// The first Identify waits nothing; a later one waits out the remaining
/// concurrency window, and a backwards clock waits at most one full window.
#[test]
fn discord_identify_spacing_first_waits_nothing() -> Check {
    let window = IDENTIFY_WINDOW_US;
    require(
        identify_wait(0, window * 10).is_none(),
        "the first Identify must not wait",
    )?;
    require(
        identify_wait(1_000, 1_000 + window / 2) == Some(Duration::from_micros(window / 2)),
        "a fresh attempt inside the window waits out the remainder",
    )?;
    require(
        identify_wait(1_000, 1_000 + window).is_none(),
        "an attempt after the full window waits nothing",
    )?;
    require(
        identify_wait(1_000, 500) == Some(Duration::from_micros(window)),
        "a backwards clock waits at most one full window",
    )?;
    Ok(())
}

/// The actual REST client validates synthetic TLS, suppresses mentions and never
/// retries an uncertain POST or follows a redirect carrying the credential.
#[test]
fn discord_wire_review_rest_send_proof_and_no_automatic_retries() -> Check {
    let f = Fixture::new("normal")?;
    runtime()?.block_on(async {
        let identity = f.adapter.identity(&f.token).await?;
        require(
            identity.id.to_string() == "9001",
            "authenticated bot identity changed",
        )?;
        let chat = ExternalId::new("2001".into())?;
        require(
            f.adapter
                .send(&f.token, &chat, "hello @everyone", &[])
                .await?
                .to_string()
                == "8001",
            "send did not return provider witness",
        )?;
        require(
            matches!(
                f.adapter.send(&f.token, &chat, "RATE", &[]).await,
                Err(Error::RateLimited {
                    retry_after_seconds: 2
                })
            ),
            "fractional provider backoff was not preserved",
        )?;
        for text in ["UNKNOWN", "REDIRECT"] {
            require(
                matches!(
                    f.adapter.send(&f.token, &chat, text, &[]).await,
                    Err(Error::SendOutcomeUnknown)
                ),
                "uncertain send became a receipt",
            )?;
        }
        require(
            matches!(
                f.adapter
                    .send(&f.token, &chat, &"😀".repeat(1001), &[])
                    .await,
                Err(Error::MessageTooLarge)
            ),
            "UTF-16 limit was not checked before send",
        )?;
        let events = f.events()?;
        let sends: Vec<_> = events.iter().filter(|e| e["kind"] == "post").collect();
        require(
            sends.len() == 4,
            "oversized/uncertain/redirect send was transmitted again",
        )?;
        require(
            sends
                .iter()
                .all(|e| e["body"]["allowed_mentions"]["parse"] == json!([])),
            "automatic mentions were enabled",
        )?;
        require(
            !events.iter().any(|e| {
                e["route"]
                    .as_str()
                    .is_some_and(|r| r.contains("unexpected"))
            }),
            "redirect reached another route",
        )?;
        f.no_fixture_errors()
    })
}

/// Sender admission uses a REST-verified one-to-one channel and the actual
/// author; groups, bots and webhooks cannot become owner input.
#[test]
fn discord_wire_review_private_human_normalization() -> Check {
    let f = Fixture::new("normalize")?;
    runtime()?.block_on(async {
        let mut receiver = ready(&f).await?;
        for sequence in 2..=9 {
            let row = next(receiver.as_mut(), &f.token).await?;
            require(row.update.to_string() == (5000 + sequence).to_string(), "dispatch reordered")?;
            match sequence {
                2 | 9 => require(matches!(&row.content, IncomingContent::Text { phone, .. } if phone.subject.to_string()=="1001" && phone.private_chat.to_string()=="2001"), "private human text lost exact sender")?,
                8 => require(matches!(row.content, IncomingContent::UnsupportedPrivate { .. }), "attachment was saved as text")?,
                _ => require(matches!(row.content, IncomingContent::Unsupported), "untrusted sender became private input")?,
            }
            receiver.ack(&row.cursor)?;
        }
        f.no_fixture_errors()
    })
}

/// Cancelling slow identity verification retains its dispatch and does not block
/// the independently maintained heartbeat stream.
#[test]
fn discord_wire_review_cancellation_and_heartbeats() -> Check {
    let f = Fixture::new("cancel")?;
    runtime()?.block_on(async {
        let mut receiver = ready(&f).await?;
        require(
            tokio::time::timeout(Duration::from_millis(100), receiver.next(&f.token))
                .await
                .is_err(),
            "identity read did not remain pending",
        )?;
        let row = next(receiver.as_mut(), &f.token).await?;
        require(
            row.update.to_string() == "5002" && matches!(row.content, IncomingContent::Text { .. }),
            "cancelled dispatch was discarded",
        )?;
        require(
            matches!(receiver.next(&f.token).await, Err(Error::InvalidInput)),
            "unacknowledged dispatch was bypassed",
        )?;
        receiver.ack(&row.cursor)?;
        let events = f.events()?;
        require(
            events.iter().filter(|e| e["kind"] == "heartbeat").count() >= 3,
            "REST lookup blocked heartbeats",
        )?;
        require(
            events
                .iter()
                .filter(|e| e["kind"] == "get" && e["route"] == "/channels/2001")
                .count()
                == 2,
            "identity read was not retried for the retained dispatch",
        )?;
        f.no_fixture_errors()
    })
}

/// A new receiver resumes after the last acknowledged cursor, even when the
/// previous socket had already observed later messages.
#[test]
fn discord_wire_review_resume_uses_durable_checkpoint() -> Check {
    let f = Fixture::new("resume")?;
    let outcome = runtime()?.block_on(async {
        let mut receiver = ready(&f).await?;
        let first = next(receiver.as_mut(), &f.token).await?;
        require(
            first.update.to_string() == "5002",
            "first private dispatch missing",
        )?;
        receiver.ack(&first.cursor)?;
        tokio::time::sleep(Duration::from_millis(80)).await;
        drop(receiver);
        let mut successor = f.adapter.clone().receiver(Some(first.cursor))?;
        let replay = next(successor.as_mut(), &f.token).await?;
        require(
            replay.update.to_string() == "5003",
            "resume skipped or repeated the durable checkpoint",
        )?;
        successor.ack(&replay.cursor)?;
        require(
            f.events()?
                .iter()
                .any(|e| e["kind"] == "gateway_auth" && e["op"] == 6 && e["seq"] == 2),
            "resume used the latest wire sequence instead of durable state",
        )?;
        f.no_fixture_errors()
    });
    if outcome.is_err() {
        f.report("discord_wire_review_resume_uses_durable_checkpoint");
    }
    outcome
}

/// Queue overflow closes the socket visibly; replay supplies every dispatch
/// after the last durable acknowledgement rather than silently dropping it.
#[test]
fn discord_wire_review_overflow_recovers_every_message() -> Check {
    let f = Fixture::new("burst")?;
    runtime()?.block_on(async {
        let mut receiver = ready(&f).await?;
        let mut seen = Vec::new();
        let mut cursor = None;
        loop {
            match tokio::time::timeout(Duration::from_secs(5), receiver.next(&f.token)).await? {
                Ok(Some(row)) => {
                    seen.push(row.update.to_string());
                    receiver.ack(&row.cursor)?;
                    cursor = Some(row.cursor);
                }
                Err(Error::ProviderUnreachable) => break,
                _ => return Err("overflow was hidden or converted to an empty result".into()),
            }
        }
        require(
            seen.len() < 32,
            "burst did not exercise bounded queue overflow",
        )?;
        let last = cursor.ok_or("no durable private dispatch before overflow")?;
        drop(receiver);
        let mut receiver = f.adapter.clone().receiver(Some(last))?;
        while seen.len() < 32 {
            let row = next(receiver.as_mut(), &f.token).await?;
            seen.push(row.update.to_string());
            receiver.ack(&row.cursor)?;
        }
        require(
            seen == (5002..5034).map(|id| id.to_string()).collect::<Vec<_>>(),
            "overflow lost or duplicated private text",
        )?;
        f.no_fixture_errors()
    })
}

/// An expired resume session is explicit and invalidated, so the subsequent
/// attempt identifies afresh instead of retrying an impossible replay forever.
#[test]
fn discord_wire_review_expired_replay_is_visible() -> Check {
    let f = Fixture::new("expired")?;
    runtime()?.block_on(async {
        let mut receiver = ready(&f).await?;
        let first = next(receiver.as_mut(), &f.token).await?;
        receiver.ack(&first.cursor)?;
        let cursor = first.cursor;
        drop(receiver);
        let mut receiver = f.adapter.clone().receiver(Some(cursor.clone()))?;
        require(
            matches!(
                tokio::time::timeout(Duration::from_secs(15), receiver.next(&f.token)).await?,
                Err(Error::ReplayUnavailable)
            ),
            "expired replay was collapsed to absence",
        )?;
        drop(receiver);
        let mut fresh = f.adapter.clone().receiver(Some(cursor))?;
        let checkpoint = next(fresh.as_mut(), &f.token).await?;
        require(
            matches!(checkpoint.content, IncomingContent::Unsupported),
            "fresh READY was not preserved as a checkpoint",
        )?;
        fresh.ack(&checkpoint.cursor)?;
        require(
            f.events()?
                .iter()
                .filter(|e| e["kind"] == "gateway_auth" && e["op"] == 2)
                .count()
                == 2,
            "invalid replay session was retried forever",
        )?;
        f.no_fixture_errors()
    })
}
