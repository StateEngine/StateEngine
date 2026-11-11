use super::*;
/// Protects: 49 — reconcile an interrupted private send as unknown without retrying or losing original mail.
#[test]
fn uncertain_provider_send_is_terminal_and_keeps_its_saved_message() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let s = paired(&f, &mut writer, &lease)?;
    let id = message()?;
    writer.append(saved(&f, &s, id.clone(), 200, "save-200")?, &*lease)?;
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    let output = view
        .channel_outbox(&s.id, 0)?
        .items
        .into_iter()
        .find(|o| o.kind == "saved")
        .ok_or("missing Saved acknowledgment")?;
    view.close()?;
    writer.append(
        change(
            &f,
            Change::OutputStarted {
                connection: s.id.clone(),
                binding_revision: s.revision,
                output: output.output.clone(),
                expected_attempt: 0,
            },
            "send-200-start",
        )?,
        &*lease,
    )?;
    // Reopening after an interrupted request retains Sending; it never resets to
    // Queued just because a worker lost its HTTP response.
    writer.close()?;
    let Read::Present { value: mut writer } = SqliteFactory::open_direct(&f.options, &*lease)?
    else {
        return Err("missing reopened store".into());
    };
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    let pending = view.channel_pending_outputs(&s.id, i64::MAX)?.items;
    assert!(
        pending
            .iter()
            .any(|o| o.output == output.output && o.state == "sending" && o.attempt == 1)
    );
    view.close()?;
    assert!(
        writer
            .append(
                change(
                    &f,
                    Change::OutputStarted {
                        connection: s.id.clone(),
                        binding_revision: s.revision,
                        output: output.output.clone(),
                        expected_attempt: 0
                    },
                    "send-200-illegal-retry"
                )?,
                &*lease
            )
            .is_err()
    );
    writer.append(
        change(
            &f,
            Change::OutputFinished {
                connection: s.id.clone(),
                output: output.output.clone(),
                attempt: 1,
                outcome: OutputOutcome::Unknown,
            },
            "send-200-unknown",
        )?,
        &*lease,
    )?;
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    assert!(
        view.channel_pending_outputs(&s.id, i64::MAX)?
            .items
            .iter()
            .all(|o| o.output != output.output)
    );
    assert!(matches!(view.message(id)?, Read::Present { .. }));
    view.close()?;
    writer.close()?;
    Ok(())
}
/// Protects: 49 — preserve an already released send result while rejecting the next revoked release.
#[test]
fn revoke_retains_inflight_success_but_prevents_next_private_release() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let s = paired(&f, &mut writer, &lease)?;
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    let output = view
        .channel_outbox(&s.id, 0)?
        .items
        .into_iter()
        .next()
        .ok_or("missing pairing acknowledgment")?;
    view.close()?;
    writer.append(
        change(
            &f,
            Change::OutputStarted {
                connection: s.id.clone(),
                binding_revision: s.revision,
                output: output.output.clone(),
                expected_attempt: 0,
            },
            "inflight-start",
        )?,
        &*lease,
    )?;
    writer.append(
        change(
            &f,
            Change::Disconnected {
                connection: s.id.clone(),
                expected: s.revision,
            },
            "revoke-inflight",
        )?,
        &*lease,
    )?;
    writer.append(
        change(
            &f,
            Change::OutputFinished {
                connection: s.id.clone(),
                output: output.output.clone(),
                attempt: 1,
                outcome: OutputOutcome::Sent {
                    provider_message: 99.into(),
                },
            },
            "inflight-finish",
        )?,
        &*lease,
    )?;
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    let actual = view
        .channel_outbox(&s.id, 0)?
        .items
        .into_iter()
        .find(|o| o.output == output.output)
        .ok_or("lost in-flight output")?;
    assert_eq!(actual.state, "sent");
    assert_eq!(actual.provider_message, Some(99.into()));
    view.close()?;
    assert!(
        writer
            .append(
                change(
                    &f,
                    Change::OutputStarted {
                        connection: s.id.clone(),
                        binding_revision: s.revision,
                        output: output.output,
                        expected_attempt: 1
                    },
                    "revoked-next-attempt"
                )?,
                &*lease
            )
            .is_err()
    );
    writer.close()?;
    Ok(())
}
/// Protects: 49 — base delayed status on elapsed committed time without creating recipient read facts.
#[test]
fn status_delay_uses_saved_commit_time_and_never_marks_mail_read() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let s = paired(&f, &mut writer, &lease)?;
    let id = message()?;
    writer.append(saved(&f, &s, id.clone(), 201, "save-201")?, &*lease)?;
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    let receipt = view
        .channel_saved(&s.id, 0)?
        .items
        .into_iter()
        .next()
        .ok_or("missing Saved receipt")?;
    assert!(
        view.channel_due_delays(&s.id, receipt.at_us + 59_999_999)?
            .is_empty()
    );
    assert_eq!(
        view.channel_due_delays(&s.id, receipt.at_us + 60_000_000)?,
        vec![id.clone()]
    );
    view.close()?;
    assert!(
        writer
            .append(
                change(
                    &f,
                    Change::DelayQueued {
                        connection: s.id.clone(),
                        binding_revision: s.revision,
                        message: id.clone()
                    },
                    "premature-status"
                )?,
                &*lease
            )
            .is_err()
    );
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    let Read::Present { value } = view.message(id)? else {
        return Err("saved mail disappeared".into());
    };
    assert!(value.read.is_none());
    view.close()?;
    writer.close()?;
    Ok(())
}

/// Protects: 49 — bound pending mail and status output while keeping read facts and failed inputs honest.
#[test]
fn pending_capacity_recovers_after_recipient_read_and_known_output_completion() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let s = paired(&f, &mut writer, &lease)?;
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    let paired = view
        .channel_outbox(&s.id, 0)?
        .items
        .into_iter()
        .next()
        .ok_or("pairing output absent")?;
    view.close()?;
    for (key, fact) in [
        (
            "capacity-pair-start",
            Change::OutputStarted {
                connection: s.id.clone(),
                binding_revision: s.revision,
                output: paired.output.clone(),
                expected_attempt: 0,
            },
        ),
        (
            "capacity-pair-sent",
            Change::OutputFinished {
                connection: s.id.clone(),
                output: paired.output,
                attempt: 1,
                outcome: OutputOutcome::Sent {
                    provider_message: 1.into(),
                },
            },
        ),
    ] {
        writer.append(change(&f, fact, key)?, &*lease)?;
    }
    let mut first = None;
    for chunk in 0..40 {
        let mut batch = f.batch(
            f.owner_project(),
            Some(request(&format!("capacity-group-{chunk}"))?),
            vec![],
        )?;
        for ordinal in 0..25 {
            let id = message()?;
            if first.is_none() {
                first = Some(id.clone());
            }
            let update = 10000 + chunk * 25 + ordinal;
            batch
                .events
                .extend(saved(&f, &s, id, update, &format!("capacity-input-{update}"))?.events);
        }
        writer.append(batch, &*lease)?;
    }
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    assert!(!view.channel_has_capacity(&s.id)?);
    let next = view
        .channel_outbox(&s.id, 0)?
        .items
        .into_iter()
        .find(|o| o.kind == "saved")
        .ok_or("Saved output absent")?;
    view.close()?;
    let blocked = message()?;
    assert!(
        writer
            .append(
                saved(&f, &s, blocked.clone(), 12000, "capacity-overflow")?,
                &*lease
            )
            .is_err()
    );
    let original = first.ok_or("original input absent")?;
    writer.append(
        f.batch(
            f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone())),
            Some(request("capacity-read")?),
            vec![EventBody::MessageRead {
                message: original.clone(),
                recipient: Actor::Agent(f.a.clone()),
            }],
        )?,
        &*lease,
    )?;
    for (key, fact) in [
        (
            "capacity-save-start",
            Change::OutputStarted {
                connection: s.id.clone(),
                binding_revision: s.revision,
                output: next.output.clone(),
                expected_attempt: 0,
            },
        ),
        (
            "capacity-save-sent",
            Change::OutputFinished {
                connection: s.id.clone(),
                output: next.output,
                attempt: 1,
                outcome: OutputOutcome::Sent {
                    provider_message: 2.into(),
                },
            },
        ),
    ] {
        writer.append(change(&f, fact, key)?, &*lease)?;
    }
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    assert!(view.channel_has_capacity(&s.id)?);
    assert!(matches!(view.message(blocked)?, Read::Absent { .. }));
    let Read::Present { value } = view.message(original)? else {
        return Err("original mail absent".into());
    };
    assert!(value.read.is_some());
    let saved = view.channel_saved(&s.id, 0)?;
    assert_eq!(saved.items.len(), 100);
    assert_eq!(saved.omitted, 900);
    view.close()?;
    writer.close()?;
    Ok(())
}
