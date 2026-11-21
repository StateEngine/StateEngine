//! Independent real TLS/Gateway/REST controls. Native Windows/macOS and a live
//! provider account are separate qualifications; this local fixture is Linux-only.
use super::test_fixture::Fixture;
use super::*;
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

/// The first Identify for a token fires now; a later one follows the previous
/// fire by at least one full window, measured on a monotonic clock.
#[test]
fn discord_identify_spacing_first_waits_nothing() -> Check {
    let now = Instant::now();
    require(
        next_identify_fire(None, now) == now,
        "the first Identify must not wait",
    )?;
    require(
        next_identify_fire(Some(now), now) == now + IDENTIFY_WINDOW,
        "an attempt at the previous fire waits the full window",
    )?;
    require(
        next_identify_fire(Some(now), now + IDENTIFY_WINDOW / 2) == now + IDENTIFY_WINDOW,
        "an attempt inside the window waits out the remainder",
    )?;
    require(
        next_identify_fire(Some(now), now + IDENTIFY_WINDOW) == now + IDENTIFY_WINDOW,
        "an attempt after the full window fires at the boundary",
    )?;
    Ok(())
}

/// An expired replay is explicit and the receiver identifies afresh. The first
/// Identify is prompt, while the next still observes the concurrency window.
#[test]
fn discord_wire_review_identify_first_is_prompt_and_later_is_spaced() -> Check {
    let f = Fixture::new("expired")?;
    f.finish(runtime()?.block_on(async {
        let started = std::time::Instant::now();
        let mut receiver = ready(&f).await?;
        require(
            started.elapsed() < Duration::from_secs(3),
            "the first Identify waited out a fixed delay",
        )?;
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
            started.elapsed() >= Duration::from_millis(4800),
            "the second fresh Identify was not spaced from the first",
        )?;
        require(
            f.events()?
                .iter()
                .filter(|event| event["kind"] == "gateway_auth" && event["op"] == 2)
                .count()
                == 2,
            "invalid replay session was retried forever",
        )?;
        Ok(())
    }))
}

/// The actual REST client validates synthetic TLS, suppresses mentions and never
/// retries an uncertain POST or follows a redirect carrying the credential.
#[test]
fn discord_wire_review_rest_send_proof_and_no_automatic_retries() -> Check {
    let f = Fixture::new("normal")?;
    f.finish(runtime()?.block_on(async {
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
        Ok(())
    }))
}

/// Sender admission uses a REST-verified one-to-one channel and the actual
/// author; groups, bots and webhooks cannot become owner input.
#[test]
fn discord_wire_review_private_human_normalization() -> Check {
    let f = Fixture::new("normalize")?;
    f.finish(runtime()?.block_on(async {
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
        Ok(())
    }))
}

/// Cancelling slow identity verification retains its dispatch and does not block
/// the independently maintained heartbeat stream.
#[test]
fn discord_wire_review_cancellation_and_heartbeats() -> Check {
    let f = Fixture::new("cancel")?;
    f.finish(runtime()?.block_on(async {
        let mut receiver = ready(&f).await?;
        let lookup = |event: &Value| event["kind"] == "get" && event["route"] == "/channels/2001";
        // The provider holds the REST reply. Drop this receive only after the
        // lookup and subsequent heartbeats reached the wire.
        tokio::select! {
            _ = receiver.next(&f.token) => return Err("identity read did not remain pending".into()),
            result = f.wait_for_events("identity lookup with three subsequent heartbeats", |events| {
                events
                    .iter()
                    .skip_while(|event| !lookup(event))
                    .filter(|event| event["kind"] == "heartbeat")
                    .count() >= 3
            }) => result?,
        }
        let (row, ()) = tokio::try_join!(next(receiver.as_mut(), &f.token), async {
            f.wait_for_events("a second lookup for the retained dispatch", |events| {
                events.iter().filter(|event| lookup(event)).count() >= 2
            })
            .await?;
            std::fs::write(f.root.join("release-channel-reads"), [])?;
            Ok(())
        })?;
        require(
            row.update.to_string() == "5002" && matches!(row.content, IncomingContent::Text { .. }),
            "cancelled dispatch was discarded",
        )?;
        require(
            matches!(receiver.next(&f.token).await, Err(Error::InvalidInput)),
            "unacknowledged dispatch was bypassed",
        )?;
        receiver.ack(&row.cursor)?;
        require(
            f.events()?.iter().filter(|event| lookup(event)).count() == 2,
            "identity read was not retried exactly once for the retained dispatch",
        )?;
        Ok(())
    }))
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
        Ok(())
    });
    if outcome.is_err() {
        f.report("discord_wire_review_resume_uses_durable_checkpoint");
    }
    f.finish(outcome)
}

/// Queue overflow closes the socket visibly; replay supplies every dispatch
/// after the last durable acknowledgement rather than silently dropping it.
#[test]
fn discord_wire_review_overflow_recovers_every_message() -> Check {
    let f = Fixture::new("burst")?;
    f.finish(runtime()?.block_on(async {
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
        Ok(())
    }))
}

/// A withheld heartbeat acknowledgement is the provider's zombied-connection
/// condition: the client closes that socket and resumes from its checkpoint
/// instead of reporting an outage, and the missed dispatch still arrives.
#[test]
fn discord_wire_review_zombie_connection_resumes_without_losing_mail() -> Check {
    let f = Fixture::new("zombie")?;
    let outcome = runtime()?.block_on(async {
        let mut receiver = ready(&f).await?;
        let first = next(receiver.as_mut(), &f.token).await?;
        receiver.ack(&first.cursor)?;
        // Idle long enough for a heartbeat to go unacknowledged, then read on.
        let second = next(receiver.as_mut(), &f.token).await?;
        require(
            second.update.to_string() == "5003",
            "the dispatch held for the resumed connection was lost",
        )?;
        receiver.ack(&second.cursor)?;
        require(
            f.events()?
                .iter()
                .any(|e| e["kind"] == "heartbeat_withheld"),
            "the provider never withheld an acknowledgement",
        )?;
        Ok(())
    });
    if outcome.is_err() {
        f.report("discord_wire_review_zombie_connection_resumes_without_losing_mail");
    }
    f.finish(outcome)
}

/// A provider that acknowledges one heartbeat per connection and then forgets the
/// socket must end as an honest unreachable: a READY or RESUMED checkpoint is not
/// progress, so the resume loop stays bounded instead of retrying forever.
#[test]
fn discord_wire_review_repeated_zombies_end_unreachable() -> Check {
    let f = Fixture::new("zombie_all")?;
    let outcome = runtime()?.block_on(async {
        let mut receiver = ready(&f).await?;
        let mut checkpoints = 0;
        loop {
            match tokio::time::timeout(Duration::from_secs(15), receiver.next(&f.token)).await? {
                Ok(Some(row)) => {
                    require(
                        !matches!(row.content, IncomingContent::Text { .. }),
                        "a dispatch arrived, so the provider was making progress",
                    )?;
                    receiver.ack(&row.cursor)?;
                    checkpoints += 1;
                }
                Err(Error::ProviderUnreachable) => break,
                _ => return Err("an endlessly zombied provider did not end unreachable".into()),
            }
        }
        require(
            checkpoints > 0,
            "the connection was never resumed before the provider was called gone",
        )?;
        Ok(())
    });
    if outcome.is_err() {
        f.report("discord_wire_review_repeated_zombies_end_unreachable");
    }
    f.finish(outcome)
}

/// Acknowledgements on every resumed connection are control traffic, not
/// progress: a provider that acks the first heartbeat of each socket and then
/// forgets it, while delivering nothing, must still end as an honest unreachable.
#[test]
fn discord_wire_review_control_traffic_does_not_extend_retries() -> Check {
    let f = Fixture::new("zombie_ack_each")?;
    let outcome = runtime()?.block_on(async {
        let mut receiver = ready(&f).await?;
        loop {
            match tokio::time::timeout(Duration::from_secs(15), receiver.next(&f.token)).await? {
                Ok(Some(row)) => {
                    require(
                        !matches!(row.content, IncomingContent::Text { .. }),
                        "a dispatch arrived, so the provider was making progress",
                    )?;
                    receiver.ack(&row.cursor)?;
                }
                Err(Error::ProviderUnreachable) => break,
                _ => return Err("control traffic kept the resume loop alive".into()),
            }
        }
        require(
            f.events()?
                .iter()
                .filter(|e| e["kind"] == "heartbeat")
                .count()
                > 1,
            "the provider never acknowledged control traffic",
        )?;
        Ok(())
    });
    if outcome.is_err() {
        f.report("discord_wire_review_control_traffic_does_not_extend_retries");
    }
    f.finish(outcome)
}
