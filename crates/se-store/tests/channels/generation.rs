use super::*;

/// Protects: 49 — a new approved connection has its own update identity while bot ACK progress survives replacement.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn reconnect_scopes_dispositions_and_retains_the_bot_ack_cursor() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let old = paired(&f, &mut writer, &lease)?;
    let original = message()?;
    let accepted = writer.append(saved(&f, &old, original.clone(), 100, "old-100")?, &*lease)?;
    writer.append(
        change(
            &f,
            Change::UpdateHandled {
                cursor: None,
                connection: old.id.clone(),
                binding_revision: old.revision,
                update: 101.into(),
                disposition: Disposition::RejectedPaired {
                    reason: Rejection::TooLarge,
                    subject: 42.into(),
                    private_chat: 42.into(),
                },
            },
            "old-rejection",
        )?,
        &*lease,
    )?;
    writer.append(
        change(
            &f,
            Change::Disconnected {
                connection: old.id.clone(),
                expected: old.revision,
            },
            "old-disconnect",
        )?,
        &*lease,
    )?;
    writer.append(
        change(
            &f,
            Change::CredentialRemoved {
                connection: old.id.clone(),
                credential: old.credential.clone(),
            },
            "old-forget",
        )?,
        &*lease,
    )?;
    let mut replacement = state(&f)?;
    replacement.id = ChannelId::new("chn-33333333333333333333333333333333")?;
    replacement.credential.id = CredentialId::new("ccr-44444444444444444444444444444444")?;
    let replacement = paired_with(&f, &mut writer, &lease, replacement)?;
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    assert!(view.channel_update_handled(&old.id, &100.into())?);
    assert!(!view.channel_update_handled(&replacement.id, &100.into())?);
    assert_eq!(
        view.channel_cursor(&replacement.id)?,
        Some(ReceiveCursor::new("101".into())?)
    );
    view.close()?;
    let new_message = message()?;
    let repeated_input = || -> Result<AtomicBatch, Box<dyn std::error::Error>> {
        let mut batch = saved(&f, &replacement, new_message.clone(), 100, "new-100")?;
        for event in &mut batch.events {
            if let EventBody::ChannelRecorded {
                change:
                    Change::UpdateHandled {
                        cursor: None,
                        disposition: Disposition::Saved { receipt, .. },
                        ..
                    },
            } = &mut event.body
            {
                *receipt = ReceiptId::new("chr-55555555555555555555555555555555")?;
            }
        }
        Ok(batch)
    };
    let new = writer.append(repeated_input()?, &*lease)?;
    let replay = writer.append(repeated_input()?, &*lease)?;
    assert_eq!(new.events, replay.events);
    assert_eq!(replay.state, CommitState::Replayed);
    assert_ne!(accepted.events, new.events);
    writer.append(
        change(
            &f,
            Change::UpdateHandled {
                cursor: None,
                connection: replacement.id.clone(),
                binding_revision: replacement.revision,
                update: 101.into(),
                disposition: Disposition::RejectedPaired {
                    reason: Rejection::Unsupported,
                    subject: 42.into(),
                    private_chat: 42.into(),
                },
            },
            "new-rejection",
        )?,
        &*lease,
    )?;
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    let old_refusal = view.channel_recent_rejections(&old.id)?;
    let new_refusal = view.channel_recent_rejections(&replacement.id)?;
    assert_eq!(old_refusal.items.len(), 1);
    assert_eq!(new_refusal.items.len(), 1);
    assert_eq!(old_refusal.items[0].reason, Rejection::TooLarge);
    assert_eq!(new_refusal.items[0].reason, Rejection::Unsupported);
    assert_eq!(
        view.channel_cursor(&replacement.id)?,
        Some(ReceiveCursor::new("101".into())?)
    );
    assert_eq!(view.channel_saved(&old.id, 0)?.items[0].message, original);
    assert_eq!(
        view.channel_saved(&replacement.id, 0)?.items[0].message,
        new_message
    );
    view.close()?;
    writer.close()?;
    Ok(())
}
