//! A sender listing its sent mail must omit the recipient's private phone
//! reply route per row, never fail the whole listing (issue 182).
#![cfg(any(target_os = "linux", windows))]

#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
use se_core::commit::Cx;
use se_core::ops::{MessageBox, MessageList, MessageView, message};
use se_store::{channel::*, *};
use std::time::{SystemTime, UNIX_EPOCH};

type Check = Result<(), Box<dyn std::error::Error>>;

fn state(f: &Fixture) -> Result<channel::Connection, Box<dyn std::error::Error>> {
    Ok(channel::Connection {
        connector: Connector::Telegram,
        id: ChannelId::new("chn-33333333333333333333333333333333")?,
        owner: f.owner.clone(),
        credential: CredentialRef {
            store: f.store.clone(),
            owner: f.owner.clone(),
            id: CredentialId::new("ccr-44444444444444444444444444444444")?,
            revision: 1,
        },
        target: ChannelTarget {
            project: f.project.clone(),
            agent: f.a.clone(),
            selection_revision: 1,
        },
        bot: BotIdentity {
            id: 23.into(),
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
    let mut s = state(f)?;
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
                    subject: 42.into(),
                    private_chat: 42.into(),
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
    id: se_types::MessageId,
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
            cursor: None,
            connection: state.id.clone(),
            binding_revision: state.revision,
            update: update.into(),
            disposition: Disposition::Saved {
                receipt: ReceiptId::new(format!("chr-{update:032x}"))?,
                message: id,
                subject: 42.into(),
                private_chat: 42.into(),
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
fn listing(mailbox: MessageBox) -> MessageList {
    MessageList {
        cli_list: false,
        view: MessageView::All,
        mailbox,
        from: None,
        kind: None,
        full: true,
        limit: 20,
        preview_chars: None,
        cursor: None,
        newest: false,
        owner_to: None,
    }
}

#[test]
fn sender_sent_listing_omits_the_recipient_phone_route() -> Check {
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    // A real project registers its owner at project scope; the fixture does not.
    writer.append(
        f.batch(
            f.owner_project(),
            Some(request("owner-project")?),
            vec![EventBody::PrincipalRegistered {
                principal: Actor::Human(f.owner.clone()),
                kind: PrincipalKind::Human,
                owner: f.owner.clone(),
                created_by: None,
                name: "owner".into(),
                role: "owner".into(),
                ephemeral: None,
                expected: Expected::Absent,
            }],
        )?,
        &*lease,
    )?;
    let s = paired(&f, &mut writer, &lease)?;
    let phone = message()?;
    writer.append(saved(&f, &s, phone.clone(), 100, "update-100")?, &*lease)?;
    let reply = message()?;
    writer.append(
        f.send(
            Actor::Agent(f.a.clone()),
            Actor::Human(f.owner.clone()),
            reply.clone(),
            "Replying to the phone ask.",
            "reply-key",
        )?,
        &*lease,
    )?;

    let admission = f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone()));

    // One snapshot at a time: the store budgets two finite read slots, and a
    // live request holds one for its lifetime.
    //
    // Sender lists its sent box: on base the recipient-private route read
    // fails the whole page; the fix omits the route on every row.
    {
        let mut sent_view = writer.snapshot(f.self_scope(&f.a))?;
        let sent = message::list(
            listing(MessageBox::Sent),
            &mut Cx {
                read: &mut sent_view,
                admission: &admission,
            },
        )?;
        let rows = sent.page.items();
        assert!(rows.iter().any(|row| row.id == reply), "reply row missing");
        for row in rows {
            assert!(
                row.channel_reply.is_none(),
                "sender view exposes the recipient-private route: {}",
                row.id
            );
        }
    }

    // The recipient still sees its own route in its inbox.
    {
        let mut inbox_view = writer.snapshot(f.self_scope(&f.a))?;
        let inbox = message::list(
            listing(MessageBox::Inbox),
            &mut Cx {
                read: &mut inbox_view,
                admission: &admission,
            },
        )?;
        let phone_row = inbox
            .page
            .items()
            .iter()
            .find(|row| row.id == phone)
            .ok_or("phone row missing from recipient inbox")?;
        let route = phone_row
            .channel_reply
            .as_ref()
            .ok_or("recipient lost its own channel route")?;
        // No phone transport runs, so the saved route is history, never live.
        assert!(!route.active);
        assert!(route.instruction.contains("does not reach that phone"));
        assert_eq!(route.reply_to, phone);
    }

    // A foreign agent still cannot read the route at the store port.
    let mut foreign = writer.snapshot(f.self_scope(&f.b))?;
    let denied = foreign
        .channel_reply_route(&phone)
        .err()
        .ok_or("foreign agent read the recipient-private route")?;
    assert_eq!(denied.code, StoreErrorCode::ScopeMismatch);

    // The native Owner still sees the route.
    let mut owner_view = writer.snapshot(f.scoped(Visibility::Owner))?;
    let route = owner_view
        .channel_reply_route(&phone)?
        .ok_or("owner lost the channel route")?;
    assert!(route.active);
    Ok(())
}
