//! Store replay contracts consumed by the host receive checkpoint fence.
//! The host race itself is not scheduled here: both replay outcomes are driven
//! deterministically through real request lookup and the SQLite writer API.
use super::*;

fn delivery(
    f: &Fixture,
    state: &channel::Connection,
    id: MessageId,
    cursor: &str,
) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    let mut batch = saved(f, state, id, 701, "checkpoint-input-replay")?;
    batch
        .request
        .as_mut()
        .ok_or("request absent")?
        .intent
        .operation = "channel.update";
    for event in &mut batch.events {
        if let EventBody::ChannelRecorded {
            change: Change::UpdateHandled { cursor: value, .. },
        } = &mut event.body
        {
            *value = Some(ReceiveCursor::new(cursor.into())?);
        }
    }
    Ok(batch)
}

#[test]
fn request_lookup_and_writer_replay_require_a_separate_current_delivery_checkpoint() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let state = paired(&f, &mut writer, &lease)?;
    let original = message()?;
    let first = writer.append(
        delivery(&f, &state, original.clone(), "opaque:zebra")?,
        &*lease,
    )?;
    // The replacement batch was planned with the same input intent before the
    // original accepted write finished. The cursor is not input identity.
    let replacement_mail = message()?;
    let replacement = delivery(&f, &state, replacement_mail.clone(), "opaque:alpha")?;
    let identity = replacement.request.clone().ok_or("request absent")?;
    let replay = writer.append(replacement, &*lease)?;
    assert_eq!(replay.state, CommitState::Replayed);
    assert_eq!(replay.events, first.events);
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    let resolved = present(view.resolve_request(&identity)?)?;
    assert_eq!(resolved.events, first.events);
    assert_eq!(
        view.channel_cursor(&state.id)?.map(|c| c.to_string()),
        Some("opaque:zebra".into())
    );
    assert!(matches!(
        view.message(replacement_mail.clone())?,
        Read::Absent { .. }
    ));
    view.close()?;
    // Both successful replay exits must reach this fence in the real receiver.
    // Each checkpoint is distinct from the deduplicated input operation.
    for (cursor, key) in [
        ("opaque:alpha", "writer-replay-checkpoint"),
        ("opaque:middle", "lookup-replay-checkpoint"),
    ] {
        writer.append(
            change(
                &f,
                Change::CursorAdvanced {
                    connection: state.id.clone(),
                    binding_revision: state.revision,
                    update: 701.into(),
                    cursor: ReceiveCursor::new(cursor.into())?,
                },
                key,
            )?,
            &*lease,
        )?;
        let reader = present(SqliteFactory::open_reader(&f.options)?)?;
        let mut view = reader.snapshot(f.scoped(Visibility::Owner))?;
        assert_eq!(
            view.channel_cursor(&state.id)?.map(|c| c.to_string()),
            Some(cursor.into())
        );
        let receipts = view.channel_saved(&state.id, 0)?;
        assert_eq!(receipts.omitted, 0);
        assert_eq!(receipts.items.len(), 1);
        assert_eq!(receipts.items[0].message, original);
        assert!(matches!(
            view.message(replacement_mail.clone())?,
            Read::Absent { .. }
        ));
        view.close()?;
    }
    // A checkpoint with no committed input must fail, never becoming ACK evidence.
    assert!(
        writer
            .append(
                change(
                    &f,
                    Change::CursorAdvanced {
                        connection: state.id.clone(),
                        binding_revision: state.revision,
                        update: 702.into(),
                        cursor: ReceiveCursor::new("opaque:uncommitted".into())?,
                    },
                    "missing-input-checkpoint"
                )?,
                &*lease
            )
            .is_err()
    );
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    assert_eq!(
        view.channel_cursor(&state.id)?.map(|c| c.to_string()),
        Some("opaque:middle".into())
    );
    view.close()?;
    writer.close()?;
    Ok(())
}
