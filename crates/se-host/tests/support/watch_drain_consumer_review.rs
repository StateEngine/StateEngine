//! Reviewer controls exercise the actual client stream after decoded-wire admission.
//! No SSH/native latency or remote authentication handshake is simulated as proof.
use super::super::connection::review_fixture::Queue;
use super::*;
use se_types::{AgentId, Cursor, Omission, ProjectId, RemoteDeviceId, RemoteGrantId};
type Check = std::result::Result<(), Box<dyn std::error::Error>>;
struct NoCredential;
impl CredentialSource for NoCredential {
    fn credential_sha256(&self) -> [u8; 32] {
        [0; 32]
    }
    fn credential(&self) -> Result<LinkSecret> {
        Err(SeError::invalid(
            "fixture",
            "no reconnect or credential access",
        ))
    }
}
fn target() -> Result<RemoteTarget> {
    Ok(RemoteTarget {
        project: ProjectId::from_parts(1_700_000_000_000, [1; 10])?,
        agent: AgentId::from_parts(1_700_000_000_000, [2; 10])?,
    })
}
fn open(
    budget: u32,
) -> std::result::Result<(Watch, Queue, Arc<AtomicBool>), Box<dyn std::error::Error>> {
    let host = RemoteHostId(se_types::Sha256::from_bytes([3; 32]));
    let fenced = Arc::new(AtomicBool::new(false));
    let target = target()?;
    let call = Arc::new(RemoteCallContext::from_verified_source(
        RemoteSourceSession {
            host,
            project: target.project.clone(),
            agent: target.agent.clone(),
            session: se_types::SessionId::from_parts(1_700_000_000_000, [4; 10])?,
            generation: se_types::Generation::new(1)?,
        },
        fenced.clone(),
    ));
    let request = RemoteWatch {
        targets: vec![target.clone()],
        visible: Some(target.clone()),
        cursors: vec![],
        budget,
        measure: true,
    };
    let device = MachineSession {
        host,
        grant: RemoteGrantId::from_parts(1_700_000_000_000, [5; 10])?,
        device: RemoteDeviceId::from_parts(1_700_000_000_000, [6; 10])?,
        subject: RemoteSubject::Machine { host },
        scope: RemoteScope {
            targets: vec![target],
            verbs: vec![RemoteVerb::Watch],
        },
        authority_revision: 1,
        expires_at: se_types::UnixMicros::new(4_000_000_000_000_000)?,
    };
    let mut queue = Queue::new(
        call.clone(),
        call.invocation(&device, RemoteRequest::Watch(request.clone()))?,
    )?;
    let client = Client {
        route: RemoteRoute {
            forward: None,
            address: "127.0.0.1:9".parse()?,
            host,
        },
        device,
        signer: Arc::new(NoCredential),
        blocking: crate::runtime::BlockingPool::new(tokio::runtime::Handle::current()),
        forwards: Arc::new(ssh::Forwards::default()),
        connection: Arc::new(Mutex::new(Some(queue.connection.clone()))),
        stopped: Arc::new(AtomicBool::new(false)),
    };
    let mut watch = Watch::new(client, call, request);
    watch.attached = Some(queue.take()?);
    Ok((watch, queue, fenced))
}
fn page(index: usize, text: usize, complete: bool) -> Result<RemoteWatchBatch> {
    let target = target()?;
    let cursor = Cursor::new(format!("record-{index}"))?;
    Ok(RemoteWatchBatch {
        schema: RemoteWatchBatch::SCHEMA.into(),
        body: RemoteWatchBody {
            observation_clock: None,
            records: vec![RemoteWatchRecord::Provisional {
                target: target.clone(),
                cursor: cursor.clone(),
                item: RemoteLiveItem {
                    item_id: format!("item-{index}"),
                    role: RemoteTurnRole::Assistant,
                    preview: RemotePreview {
                        text: "x".repeat(text),
                        complete: true,
                        omitted_utf8_bytes: Omission::None,
                    },
                },
                observation: None,
            }],
            cursors: vec![RemoteCursorSet {
                target,
                durable: None,
                live: Some(cursor),
            }],
            complete,
            omitted_records: if complete {
                Omission::None
            } else {
                Omission::Unknown {
                    reason: OmissionReason::Budget,
                }
            },
            reset_required: false,
        },
    })
}
fn items(page: &RemoteWatchBatch) -> Vec<&str> {
    page.records
        .iter()
        .filter_map(|r| match r {
            RemoteWatchRecord::Provisional { item, .. } => Some(item.item_id.as_str()),
            _ => None,
        })
        .collect()
}
#[tokio::test]
async fn ready_pages_leave_the_real_stream_in_order_in_one_call() -> Check {
    let (mut watch, queue, _) = open(65536)?;
    for i in 1..=5 {
        queue.feed(page(i, 8, i == 5)?)?;
    }
    let result = watch.next(Duration::ZERO).await?;
    assert_eq!(
        items(&result),
        vec!["item-1", "item-2", "item-3", "item-4", "item-5"]
    );
    assert_eq!(
        result.cursors[0].live.as_ref().map(|c| c.as_str()),
        Some("record-5")
    );
    assert!(result.complete);
    assert!(watch.next(Duration::ZERO).await?.records.is_empty());
    drop(watch);
    assert_eq!(queue.available_bytes(), REMOTE_CLIENT_QUEUE_BYTES);
    Ok(())
}
#[tokio::test]
async fn byte_limited_page_is_deferred_with_its_original_cursor() -> Check {
    let (mut watch, queue, _) = open(2048)?;
    for i in 1..=3 {
        queue.feed(page(i, 1000, i == 3)?)?;
    }
    for i in 1..=3 {
        let result = watch.next(Duration::ZERO).await?;
        assert_eq!(items(&result), vec![format!("item-{i}").as_str()]);
        assert_eq!(
            result.cursors[0].live.as_ref().map(|c| c.as_str()),
            Some(format!("record-{i}").as_str())
        );
        assert!(wire::encode(&result, Phase::Authenticated)?.len() <= 2048);
        if i < 3 {
            assert!(!result.complete);
            assert!(queue.available_bytes() < REMOTE_CLIENT_QUEUE_BYTES);
        }
    }
    assert!(watch.next(Duration::ZERO).await?.records.is_empty());
    drop(watch);
    assert_eq!(queue.available_bytes(), REMOTE_CLIENT_QUEUE_BYTES);
    Ok(())
}
#[tokio::test]
async fn gap_and_reset_are_returned_before_later_private_output() -> Check {
    for reset in [false, true] {
        let (mut watch, queue, _) = open(65536)?;
        queue.feed(page(1, 8, true)?)?;
        let mut gap = page(2, 8, false)?;
        gap.records = vec![RemoteWatchRecord::Gap {
            target: target()?,
            reason: "synthetic discontinuity".into(),
            reset_required: reset,
        }];
        gap.reset_required = reset;
        gap.cursors.clear();
        queue.feed(gap)?;
        queue.feed(page(3, 8, true)?)?;
        assert_eq!(items(&watch.next(Duration::ZERO).await?), vec!["item-1"]);
        let barrier = watch.next(Duration::ZERO).await?;
        assert!(matches!(
            barrier.records.as_slice(),
            [RemoteWatchRecord::Gap { .. }]
        ));
        assert_eq!(barrier.reset_required, reset);
        assert_eq!(items(&watch.next(Duration::ZERO).await?), vec!["item-3"]);
    }
    Ok(())
}
#[tokio::test]
async fn observation_epochs_cannot_share_one_page() -> Check {
    let (mut watch, queue, _) = open(65536)?;
    for i in 1..=2 {
        let mut p = page(i, 8, true)?;
        p.observation_clock = Some(RemoteObservationClock {
            epoch: [i as u8; 16],
            sampled_at_us: 100,
            source_bracket_us: None,
            source_released_at_us: None,
        });
        queue.feed(p)?;
    }
    for i in 1..=2 {
        let p = watch.next(Duration::ZERO).await?;
        assert_eq!(items(&p), vec![format!("item-{i}").as_str()]);
        assert_eq!(
            p.observation_clock.as_ref().map(|c| c.epoch),
            Some([i as u8; 16])
        );
    }
    Ok(())
}
#[tokio::test]
async fn a_fenced_source_or_closed_connection_releases_no_queued_private_records() -> Check {
    let (mut watch, queue, fence) = open(65536)?;
    queue.feed(page(1, 8, true)?)?;
    fence.store(true, Ordering::Release);
    assert_eq!(
        watch
            .next(Duration::ZERO)
            .await
            .err()
            .ok_or("revoked source unexpectedly returned output")?
            .code(),
        se_types::Code::CapabilityInvalid
    );
    drop(watch);
    assert_eq!(queue.available_bytes(), REMOTE_CLIENT_QUEUE_BYTES);
    let (mut watch, queue, _) = open(65536)?;
    queue.feed(page(2, 8, true)?)?;
    queue.connection.close().await?;
    let result = watch.next(Duration::ZERO).await?;
    assert!(items(&result).is_empty());
    assert!(
        result
            .records
            .iter()
            .all(|r| matches!(r, RemoteWatchRecord::Gap { .. }))
    );
    drop(watch);
    assert_eq!(queue.available_bytes(), REMOTE_CLIENT_QUEUE_BYTES);
    Ok(())
}
