use super::*;
fn setup(
    f: &Fixture,
    writer: &mut SqliteDirect,
    lease: &Lease,
) -> Result<(channel::Connection, ResumeAction), Box<dyn std::error::Error>> {
    writer.append(
        f.batch(
            f.owner_project(),
            Some(request("resume-profile")?),
            vec![EventBody::ProfileSaved {
                agent: f.a.clone(),
                profile: Profile {
                    provider: Provider::Claude,
                    model: None,
                    permission: PermissionProfile::WorkspaceWrite,
                    named_profile: "safe".into(),
                    effort: None,
                },
                expected: Expected::Absent,
            }],
        )?,
        lease,
    )?;
    let mut s = state(f)?;
    s.policy = ChannelPolicy::ConfirmResume {
        profile: "safe".into(),
        profile_revision: 1,
        cost_limit: None,
    };
    s.resume_configuration = Some([8; 32]);
    let s = paired_with(f, writer, lease, s)?;
    let message = message()?;
    writer.append(saved(f, &s, message.clone(), 300, "resume-mail")?, lease)?;
    let action = ResumeAction {
        id: ActionId::new("cha-33333333333333333333333333333333")?,
        connection: s.id.clone(),
        binding_revision: s.revision,
        message,
        target: ResumeTarget {
            principal_revision: 1,
            profile_revision: 1,
            previous_session_event: None,
            conversation: None,
            configuration: [8; 32],
        },
        subject: 42,
        private_chat: 42,
        expires_at_us: i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros())?
            + 300000000,
        state: "offered".into(),
        code: None,
    };
    writer.append(
        change(
            f,
            Change::ResumeOffered {
                action: action.clone(),
            },
            "resume-offer",
        )?,
        lease,
    )?;
    Ok((s, action))
}
fn confirm(
    f: &Fixture,
    s: &channel::Connection,
    a: &ResumeAction,
) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    change(
        f,
        Change::ResumeConfirmed {
            connection: s.id.clone(),
            action: a.id.clone(),
            subject: 42,
            private_chat: 42,
        },
        "resume-confirm",
    )
}
fn release(
    f: &Fixture,
    s: &channel::Connection,
    a: &ResumeAction,
    session: se_types::SessionId,
    key: &str,
) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    let mut batch = f.batch(
        f.owner_project(),
        Some(request(key)?),
        vec![
            EventBody::SessionPrepared {
                session: session.clone(),
                agent: f.a.clone(),
                provider: Provider::Claude,
                surface: Some(SessionSurface::Headless),
                native_ref: "first-managed-conversation".into(),
                consent: Consent::Capture,
                generation: 1,
                expected: Expected::Absent,
            },
            EventBody::ChannelRecorded {
                change: Change::ResumeReleased {
                    connection: s.id.clone(),
                    action: a.id.clone(),
                    session,
                },
            },
        ],
    )?;
    for e in &mut batch.events {
        e.header.door = Door::Host;
    }
    Ok(batch)
}
/// Protects: 49 — recover a scoped phone confirmation and consume it exactly once with normal C1 preparation.
#[test]
fn paired_confirmation_recovers_and_is_consumed_only_with_same_transaction_preparation() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let (s, a) = setup(&f, &mut writer, &lease)?;
    assert!(
        writer
            .append(
                change(
                    &f,
                    Change::ResumeConfirmed {
                        connection: s.id.clone(),
                        action: a.id.clone(),
                        subject: 43,
                        private_chat: 43
                    },
                    "wrong-phone"
                )?,
                &*lease
            )
            .is_err()
    );
    writer.append(confirm(&f, &s, &a)?, &*lease)?;
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    assert_eq!(view.channel_confirmed_actions(&s.id)?.len(), 1);
    view.close()?;
    let session = se_types::SessionId::from_parts(1_700_000_000_005, [9; 10])?;
    assert!(
        writer
            .append(
                change(
                    &f,
                    Change::ResumeReleased {
                        connection: s.id.clone(),
                        action: a.id.clone(),
                        session: session.clone()
                    },
                    "release-without-preparation"
                )?,
                &*lease
            )
            .is_err()
    );
    let wrong_session = se_types::SessionId::from_parts(1_700_000_000_008, [12; 10])?;
    let mut wrong = release(&f, &s, &a, wrong_session.clone(), "wrong-agent-c1")?;
    if let EventBody::SessionPrepared { agent, .. } = &mut wrong.events[0].body {
        *agent = f.b.clone();
    } else {
        return Err("preparation kind".into());
    }
    assert!(writer.append(wrong, &*lease).is_err());
    writer.close()?;
    let Read::Present { value: mut writer } = SqliteFactory::open_direct(&f.options, &*lease)?
    else {
        return Err("store absent".into());
    };
    writer.append(release(&f, &s, &a, session, "guarded-c1")?, &*lease)?;
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    let Read::Present { value } = view.channel_action(&s.id, &a.id)? else {
        return Err("lost action".into());
    };
    assert_eq!(value.state, "released");
    assert!(view.channel_confirmed_actions(&s.id)?.is_empty());
    view.close()?;
    let second = se_types::SessionId::from_parts(1_700_000_000_006, [10; 10])?;
    assert!(
        writer
            .append(
                release(&f, &s, &a, second.clone(), "reuse-consumed-action")?,
                &*lease
            )
            .is_err()
    );
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    assert!(matches!(view.session(second)?, Read::Absent { .. }));
    view.close()?;
    writer.close()?;
    Ok(())
}
/// Protects: 49 — reject a stale profile grant atomically while keeping saved mail pending.
#[test]
fn changed_profile_rolls_back_phone_launch_preparation_and_preserves_original_mail() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let (s, a) = setup(&f, &mut writer, &lease)?;
    writer.append(confirm(&f, &s, &a)?, &*lease)?;
    writer.append(
        f.batch(
            f.owner_project(),
            Some(request("profile-changed")?),
            vec![EventBody::ProfileSaved {
                agent: f.a.clone(),
                profile: Profile {
                    provider: Provider::Claude,
                    model: None,
                    permission: PermissionProfile::ReadOnly,
                    named_profile: "different".into(),
                    effort: None,
                },
                expected: revision(1)?,
            }],
        )?,
        &*lease,
    )?;
    let session = se_types::SessionId::from_parts(1_700_000_000_007, [11; 10])?;
    assert!(
        writer
            .append(
                release(&f, &s, &a, session.clone(), "stale-profile-c1")?,
                &*lease
            )
            .is_err()
    );
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    assert!(matches!(view.session(session)?, Read::Absent { .. }));
    assert!(matches!(view.message(a.message)?, Read::Present { .. }));
    view.close()?;
    writer.close()?;
    Ok(())
}
/// Protects: 49 — revoke phone lifecycle authority before an unconsumed confirmation can act.
#[test]
fn disconnect_revokes_unconsumed_phone_action() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let (s, a) = setup(&f, &mut writer, &lease)?;
    writer.append(
        change(
            &f,
            Change::Disconnected {
                connection: s.id.clone(),
                expected: s.revision,
            },
            "revoke-offer",
        )?,
        &*lease,
    )?;
    assert!(writer.append(confirm(&f, &s, &a)?, &*lease).is_err());
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    assert!(view.channel_confirmed_actions(&s.id)?.is_empty());
    view.close()?;
    writer.close()?;
    Ok(())
}

/// Protects: 49 — retain lifecycle refusal and stop automatic confirmation retries without losing mail.
#[test]
fn native_lifecycle_failure_is_durable_and_does_not_requeue_confirmation() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let (s, a) = setup(&f, &mut writer, &lease)?;
    writer.append(confirm(&f, &s, &a)?, &*lease)?;
    writer.append(
        change(
            &f,
            Change::ResumeFailed {
                connection: s.id.clone(),
                action: a.id.clone(),
                code: "source-unreadable".into(),
            },
            "native-resume-failure",
        )?,
        &*lease,
    )?;
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    let Read::Present { value } = view.channel_action(&s.id, &a.id)? else {
        return Err("lost action".into());
    };
    assert_eq!(value.state, "failed");
    assert_eq!(value.code.as_deref(), Some("source-unreadable"));
    assert!(view.channel_confirmed_actions(&s.id)?.is_empty());
    assert!(matches!(view.message(a.message)?, Read::Present { .. }));
    view.close()?;
    writer.close()?;
    Ok(())
}
