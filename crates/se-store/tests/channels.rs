//! Real SQLite writer regressions for channel/mail atomicity and revocation.
#![cfg(any(target_os = "linux", windows))]
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
use se_store::{channel::*, *};
use se_types::{MessageId, Read};
use std::time::{SystemTime, UNIX_EPOCH};

fn state(f: &Fixture) -> Result<channel::Connection, Box<dyn std::error::Error>> {
    Ok(channel::Connection {
        id: ChannelId::new("chn-11111111111111111111111111111111")?,
        owner: f.owner.clone(),
        credential: CredentialRef {
            store: f.store.clone(),
            owner: f.owner.clone(),
            id: CredentialId::new("ccr-22222222222222222222222222222222")?,
            revision: 1,
        },
        target: ChannelTarget {
            project: f.project.clone(),
            agent: f.a.clone(),
            selection_revision: 1,
        },
        bot: BotIdentity {
            id: 23,
            username: "demo_bot".into(),
            display_name: "Demo".into(),
        },
        policy: ChannelPolicy::SaveOnly,
        pairing: Pairing::Challenge {
            digest: [7; 32],
            expires_at_us: i64::try_from(
                SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros(),
            )? + 600_000_000,
        },
        revision: 1,
        credential_removed: false,
        resume_configuration: None,
    })
}
fn change(f: &Fixture, fact: Change, key: &str) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    let mut b = f.batch(
        f.owner_project(),
        Some(request(key)?),
        vec![EventBody::ChannelRecorded { change: fact }],
    )?;
    for e in &mut b.events {
        e.header.door = Door::Host;
    }
    Ok(b)
}
fn paired(
    f: &Fixture,
    store: &mut SqliteDirect,
    lease: &Lease,
) -> Result<channel::Connection, Box<dyn std::error::Error>> {
    paired_with(f, store, lease, state(f)?)
}
fn paired_with(
    f: &Fixture,
    store: &mut SqliteDirect,
    lease: &Lease,
    mut s: channel::Connection,
) -> Result<channel::Connection, Box<dyn std::error::Error>> {
    store.append(
        change(
            f,
            Change::Connected {
                connection: s.clone(),
            },
            &format!("channel-connect-{}", s.id),
        )?,
        lease,
    )?;
    store.append(
        change(
            f,
            Change::PairingSeen {
                connection: s.id.clone(),
                expected: 1,
                digest: [7; 32],
                phone: PhoneIdentity {
                    subject: 42,
                    private_chat: 42,
                    display_name: "Phone".into(),
                    username: None,
                },
            },
            &format!("phone-seen-{}", s.id),
        )?,
        lease,
    )?;
    store.append(
        change(
            f,
            Change::PairingConfirmed {
                connection: s.id.clone(),
                expected: 2,
            },
            &format!("owner-approve-{}", s.id),
        )?,
        lease,
    )?;
    s.revision = 3;
    Ok(s)
}
fn saved(
    f: &Fixture,
    state: &channel::Connection,
    id: MessageId,
    update: i64,
    key: &str,
) -> Result<AtomicBatch, Box<dyn std::error::Error>> {
    let mut b = f.send(
        Actor::Human(f.owner.clone()),
        Actor::Agent(f.a.clone()),
        id.clone(),
        "Please do this and send a linked reply to my phone",
        key,
    )?;
    let mut metadata = change(
        f,
        Change::UpdateHandled {
            connection: state.id.clone(),
            binding_revision: state.revision,
            update,
            disposition: Disposition::Saved {
                receipt: ReceiptId::new(format!("chr-{update:032x}"))?,
                message: id,
                subject: 42,
                private_chat: 42,
            },
        },
        "unused",
    )?;
    for e in &mut b.events {
        e.header.door = Door::Host;
    }
    b.events.append(&mut metadata.events);
    Ok(b)
}
/// Protects: 49 — commit phone deduplication and ordinary mail atomically, retaining one original receipt.
#[test]
fn saved_receipt_is_atomic_with_mail_and_duplicate_keeps_one_message() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let s = paired(&f, &mut writer, &lease)?;
    let id = message()?;
    let batch = saved(&f, &s, id.clone(), 100, "update-100")?;
    let first = writer.append(batch, &*lease)?;
    let replay = writer.append(saved(&f, &s, id.clone(), 100, "update-100")?, &*lease)?;
    assert_eq!(first.events, replay.events);
    assert_eq!(replay.state, CommitState::Replayed);
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    let receipt = view.channel_saved(&s.id, 0)?;
    assert_eq!(receipt.items.len(), 1);
    assert_eq!(receipt.items[0].message, id.clone());
    assert_eq!(view.channel_offset(&s.id)?, Some(101));
    assert!(matches!(view.message(id)?, Read::Present { .. }));
    view.close()?;
    // A second key for the same provider update must roll its new mail back.
    let other = message()?;
    assert!(
        writer
            .append(
                saved(&f, &s, other.clone(), 100, "duplicate-other-key")?,
                &*lease
            )
            .is_err()
    );
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    assert!(matches!(view.message(other)?, Read::Absent { .. }));
    view.close()?;
    writer.close()?;
    Ok(())
}
/// Protects: 49 — refuse revoked input without saving mail or acknowledging its provider offset.
#[test]
fn stale_revoked_input_rolls_back_mail_and_does_not_advance_offset() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let s = paired(&f, &mut writer, &lease)?;
    let candidate = message()?;
    let pending = saved(&f, &s, candidate.clone(), 101, "revoked-update")?;
    writer.append(
        change(
            &f,
            Change::Disconnected {
                connection: s.id.clone(),
                expected: 3,
            },
            "disconnect",
        )?,
        &*lease,
    )?;
    assert!(writer.append(pending, &*lease).is_err());
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    assert!(matches!(view.message(candidate)?, Read::Absent { .. }));
    assert_eq!(view.channel_offset(&s.id)?, None);
    view.close()?;
    writer.close()?;
    Ok(())
}
/// Protects: 49 — forward only the approved recipient's exact linked reply and fence queued release on revoke.
#[test]
fn only_verified_linked_reply_enters_outbox_and_revoke_fences_release() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let s = paired(&f, &mut writer, &lease)?;
    writer.append(
        f.batch(
            f.owner_project(),
            Some(request("project-owner")?),
            vec![EventBody::PrincipalRegistered {
                principal: Actor::Human(f.owner.clone()),
                kind: PrincipalKind::Human,
                owner: f.owner.clone(),
                created_by: None,
                name: "Owner".into(),
                role: "owner".into(),
                expected: Expected::Absent,
            }],
        )?,
        &*lease,
    )?;
    let original = message()?;
    writer.append(saved(&f, &s, original.clone(), 102, "update-102")?, &*lease)?;
    for (sender, key) in [(f.b.clone(), "wrong-agent"), (f.a.clone(), "right-agent")] {
        let mut b = f.send(
            Actor::Agent(sender),
            Actor::Human(f.owner.clone()),
            message()?,
            "Answer",
            key,
        )?;
        if let EventBody::MessageSent { reply_to, .. } = &mut b.events[0].body {
            *reply_to = Some(original.clone());
        }
        writer.append(b, &*lease)?;
    }
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    let outbox = view.channel_outbox(&s.id, 0)?;
    assert_eq!(outbox.items.iter().filter(|r| r.kind == "reply").count(), 1);
    let output = outbox
        .items
        .iter()
        .find(|r| r.kind == "reply")
        .ok_or("missing reply")?
        .output
        .clone();
    view.close()?;
    writer.append(
        change(
            &f,
            Change::Disconnected {
                connection: s.id.clone(),
                expected: 3,
            },
            "disconnect",
        )?,
        &*lease,
    )?;
    assert!(
        writer
            .append(
                change(
                    &f,
                    Change::OutputStarted {
                        connection: s.id.clone(),
                        binding_revision: 3,
                        output,
                        expected_attempt: 0
                    },
                    "release-after-revoke"
                )?,
                &*lease
            )
            .is_err()
    );
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    assert_eq!(view.channel_outbox(&s.id, 0)?.items[0].state, "revoked");
    view.close()?;
    writer.close()?;
    Ok(())
}
/// Protects: 49 — require exact credential removal and prevent reuse while forgetting remains pending.
#[test]
fn forget_requires_exact_revision_and_reconnect_waits_for_removal() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let s = paired(&f, &mut writer, &lease)?;
    writer.append(
        change(
            &f,
            Change::Disconnected {
                connection: s.id.clone(),
                expected: 3,
            },
            "disconnect",
        )?,
        &*lease,
    )?;
    let mut next = state(&f)?;
    next.id = ChannelId::new("chn-33333333333333333333333333333333")?;
    assert!(
        writer
            .append(
                change(
                    &f,
                    Change::Connected {
                        connection: next.clone()
                    },
                    "reuse-before-forget"
                )?,
                &*lease
            )
            .is_err()
    );
    let mut wrong = s.credential.clone();
    wrong.revision = 2;
    assert!(
        writer
            .append(
                change(
                    &f,
                    Change::CredentialRemoved {
                        connection: s.id.clone(),
                        credential: wrong
                    },
                    "forget-wrong-revision"
                )?,
                &*lease
            )
            .is_err()
    );
    writer.append(
        change(
            &f,
            Change::CredentialRemoved {
                connection: s.id.clone(),
                credential: s.credential.clone(),
            },
            "forget-exact",
        )?,
        &*lease,
    )?;
    next.credential.revision = 2;
    writer.append(
        change(
            &f,
            Change::Connected { connection: next },
            "reconnect-new-revision",
        )?,
        &*lease,
    )?;
    writer.close()?;
    Ok(())
}
/// Protects: 49 — exclude private channel metadata from agent views and reject malformed identifiers.
#[test]
fn agent_visibility_and_malformed_identifiers_refuse_channel_state() -> Check {
    assert!(ChannelId::new("chn-short").is_err());
    assert!(serde_json::from_str::<ChannelId>("\"chn-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"").is_err());
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    let s = paired(&f, &mut writer, &lease)?;
    let mut view = writer.snapshot(f.self_scope(&f.a))?;
    assert!(view.channel_connection(&s.id).is_err());
    view.close()?;
    writer.close()?;
    Ok(())
}

#[path = "channels/outbox.rs"]
mod outbox;

#[path = "channels/resume.rs"]
mod resume;

#[path = "channels/generation.rs"]
mod generation;

#[path = "channels/migration.rs"]
mod migration;
