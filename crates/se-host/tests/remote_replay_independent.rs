//! Bug: durable remote replay must retain message dispositions and resolve a committed keyed send after its target session ends.
#![cfg(feature = "remote")]
use se_store::remote::*;
use se_store::*;
use se_types::{IdempotencyKey, remote::*};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
#[allow(dead_code, reason = "only native session setup helpers are used")]
mod capture;
fn rev(n: u64) -> Result<Revision, Box<dyn std::error::Error>> {
    Ok(Revision {
        value: std::num::NonZeroU64::new(n).ok_or("zero revision")?,
    })
}
fn now() -> Result<i64, Box<dyn std::error::Error>> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_micros()
        .try_into()?)
}
fn setup(
    f: &Fixture,
    d: &mut SqliteDirect,
    l: &Lease,
) -> Result<GrantRecord, Box<dyn std::error::Error>> {
    let at = now()?;
    let scope = RemoteScope {
        targets: vec![RemoteTarget {
            project: f.project.clone(),
            agent: f.a.clone(),
        }],
        verbs: vec![RemoteVerb::List, RemoteVerb::Watch, RemoteVerb::Send],
    };
    let host = RemoteHostId(se_types::Sha256::from_bytes([22; 32]));
    let grant = GrantRecord {
        grant: RemoteGrantId::from_parts(1_700_000_000_000, [24; 10])?,
        principal: RemotePrincipalId::from_parts(1_700_000_000_000, [25; 10])?,
        device: RemoteDeviceId::from_parts(1_700_000_000_000, [26; 10])?,
        credential_sha256: CredentialDigest([27; 32]),
        host,
        store: f.store.clone(),
        subject: RemoteSubject::Machine {
            host: RemoteHostId(se_types::Sha256::from_bytes([28; 32])),
        },
        scope,
        issued_at_us: at,
        last_use_at_us: at,
        expires_at_us: at + GRANT_INACTIVITY_US,
        authority_revision: rev(1)?,
        lease_revision: rev(1)?,
        state: GrantState::Active,
    };
    d.append(
        f.batch(
            f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
            Some(request("connect")?),
            vec![EventBody::RemoteSecurity {
                transition: SecurityTransition::Connect {
                    grant: Box::new(grant.clone()),
                },
            }],
        )?,
        l,
    )?;
    d.append(
        f.batch(
            f.owner_project(),
            Some(request("profile")?),
            vec![EventBody::ProfileSaved {
                agent: f.a.clone(),
                profile: Profile {
                    provider: Provider::Claude,
                    model: None,
                    permission: PermissionProfile::WorkspaceWrite,
                    named_profile: "workspace-write".into(),
                    effort: None,
                },
                expected: Expected::Absent,
            }],
        )?,
        l,
    )?;
    Ok(grant)
}
/// Bug: authorized sender replay loses a normal recipient read of its sent message.
#[test]
fn sent_message_read_is_retained_in_authorized_sender_replay() -> Check {
    let f = Fixture::new()?;
    let (mut d, l) = f.direct()?;
    let g = setup(&f, &mut d, &l)?;
    let id = message()?;
    d.append(
        f.send(
            Actor::Agent(f.a.clone()),
            Actor::Agent(f.b.clone()),
            id.clone(),
            "outgoing authorized message",
            "outgoing",
        )?,
        &*l,
    )?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let target = &g.scope.targets[0];
    let phase = reader.read_phase()?;
    let before = phase.remote_changes(
        &g.grant,
        rev(1)?,
        target,
        ChangeRequest {
            after: None,
            limit: 100,
            budget: 65536,
        },
        now()?,
    )?;
    assert!(before.changes.iter().any(|c|matches!(&c.kind,ChangeKind::Durable(RemoteDurableEvent::Message {message,delivery:RemoteDeliveryState::Pending}) if message==&id)));
    phase.close()?;
    let read = d.append(
        f.batch(
            f.self_scope(&f.b).admission,
            None,
            vec![EventBody::MessageRead {
                message: id.clone(),
                recipient: Actor::Agent(f.b.clone()),
            }],
        )?,
        &*l,
    )?;
    let mut recipient = reader.snapshot(f.self_scope(&f.b))?;
    assert_eq!(
        present(recipient.message(id.clone())?)?.read,
        Some(read.last.clone())
    );
    recipient.close()?;
    let mut sender = reader.snapshot(f.self_scope(&f.a))?;
    assert_eq!(present(sender.message(id.clone())?)?.read, Some(read.last));
    sender.close()?;
    let phase = reader.read_phase()?;
    let after = phase.remote_changes(
        &g.grant,
        rev(1)?,
        target,
        ChangeRequest {
            after: before.through.as_ref(),
            limit: 100,
            budget: 65536,
        },
        now()?,
    )?;
    let found=after.changes.iter().any(|c|matches!(&c.kind,ChangeKind::Durable(RemoteDurableEvent::Message {message,delivery:RemoteDeliveryState::Read}) if message==&id));
    phase.close()?;
    d.close()?;
    assert!(
        found,
        "ordinary recipient read committed, but authorized sender replay omitted its disposition"
    );
    Ok(())
}
/// Bug: an already committed keyed send stops resolving when its target ends normally.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn committed_send_retry_resolves_original_receipt_after_target_session_end() -> Check {
    let f = Fixture::new()?;
    let (mut d, l) = f.direct()?;
    let g = setup(&f, &mut d, &l)?;
    let session = capture::session()?;
    d.append(
        f.batch(
            f.owner_project(),
            Some(request("session")?),
            vec![
                capture::prepared(&f, &session, &f.a),
                capture::activated(&session)?,
            ],
        )?,
        &*l,
    )?;
    let send = RemoteSend {
        target: g.scope.targets[0].clone(),
        session: session.clone(),
        body: se_types::Body::new("exact same committed body")?,
        idempotency_key: IdempotencyKey::new("stable-remote-send")?,
    };
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let plan = |send: &RemoteSend| -> Result<AtomicBatch, Box<dyn std::error::Error>> {
        let admission = se_core::remote::authorize(
            g.clone(),
            RemoteVerb::Send,
            std::slice::from_ref(&send.target),
            now()?,
        )?;
        Ok(se_core::remote::plan_send(
            admission,
            send.clone(),
            RemoteAttribution {
                host: g.host,
                store: g.store.clone(),
                principal: g.principal.clone(),
                grant: g.grant.clone(),
                device: g.device.clone(),
                authority_revision: 1,
                source: None,
            },
            se_core::remote::RemoteSendFacts {
                store: reader.info()?,
                generation: 1,
                occurred_at_us: now()?,
                message: message()?,
                sent_event: event()?,
                attribution_event: event()?,
            },
        )?)
    };
    let first = d.append(plan(&send)?, &*l)?;
    // A remote message remains visible in the landed Atlas adapter with its
    // real device provenance, without granting that device Atlas authority.
    {
        use se_types::code::*;
        let scope = f.self_scope(&f.a);
        let mut snapshot = reader.snapshot(scope.clone())?;
        let source = present(snapshot.event(first.primary_event.clone())?)?;
        let EventBody::MessageSent { message, .. } = source.body else {
            return Err("send primary event is not ordinary mail".into());
        };
        let pointer = RecordPointer {
            key: RecordKey::new(message.as_str())?,
            kind: RecordKind::Message,
            source_event: first.primary_event.clone(),
        };
        let mut records =
            se_core::atlas_records::RecordAccess::new(&mut snapshot, &scope.admission);
        let hit = present(records.hit(
            &f.project,
            &AtlasPrincipal::Agent(f.a.clone()),
            &pointer,
            None,
        )?)?;
        let actor = hit.actor.ok_or("Atlas dropped remote sender attribution")?;
        assert_eq!(actor.principal, AtlasPrincipal::Remote(g.principal.clone()));
        assert_eq!(hit.line, "exact same committed body");
        assert!(
            records
                .hit(
                    &f.project,
                    &AtlasPrincipal::Remote(g.principal.clone()),
                    &pointer,
                    None
                )
                .is_err()
        );
        snapshot.close()?;
    }
    let replay = d.append(plan(&send)?, &*l)?;
    assert_eq!(replay.state, CommitState::Replayed);
    assert_eq!(replay.primary_event, first.primary_event);
    d.append(
        f.batch(
            f.owner_project(),
            Some(request("session-end")?),
            vec![EventBody::SessionEnded {
                session: session.clone(),
                expected: revision(2)?,
                reason: InputText::Inline("completed normally".into()),
                final_turn: None,
                final_cursor: None,
            }],
        )?,
        &*l,
    )?;
    let mut fresh = send.clone();
    fresh.idempotency_key = IdempotencyKey::new("fresh-send-after-target-end")?;
    assert!(
        d.append(plan(&fresh)?, &*l).is_err(),
        "new send must still require an active target session"
    );
    let mut conflict = send.clone();
    conflict.body = se_types::Body::new("different body under original key")?;
    assert!(
        d.append(plan(&conflict)?, &*l).is_err(),
        "same-key changed-body retry must remain a conflict"
    );
    let retry = d.append(plan(&send)?, &*l);
    d.close()?;
    let retry = retry.map_err(|e| {
        format!("committed send became unresolvable after normal target session end: {e}")
    })?;
    assert_eq!(retry.state, CommitState::Replayed);
    assert_eq!(retry.primary_event, first.primary_event);
    Ok(())
}

/// Bug: recipient-addressed shared work mail updates the ordinary inbox but vanishes from remote replay.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn shared_work_message_addressed_to_granted_agent_is_not_silently_skipped() -> Check {
    let f = Fixture::new()?;
    let (mut d, l) = f.direct()?;
    let g = setup(&f, &mut d, &l)?;
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let phase = reader.read_phase()?;
    let before = phase.remote_changes(
        &g.grant,
        rev(1)?,
        &g.scope.targets[0],
        ChangeRequest {
            after: None,
            limit: 100,
            budget: 65536,
        },
        now()?,
    )?;
    phase.close()?;
    let id = message()?;
    d.append(
        f.batch(
            f.owner_project(),
            Some(request("addressed-work-mail")?),
            vec![EventBody::WorkMessageSent {
                message: id.clone(),
                work: se_types::WorkAddressing {
                    action: se_types::WorkAction::Finding,
                    addressees: vec![f.a.clone(), f.b.clone()],
                },
                kind: "finding".into(),
                body: InputText::Inline(
                    "one shared body for the exact addressed recipients".into(),
                ),
                refs: vec![],
                reply_to: None,
                quiet: false,
            }],
        )?,
        &*l,
    )?;
    let mut recipient = reader.snapshot(f.self_scope(&f.a))?;
    let inbox = recipient.messages(
        query(Some(Actor::Agent(f.a.clone())), true),
        budget(20, 65536, None)?,
    )?;
    assert!(inbox.items().iter().any(|m| m.message == id));
    recipient.close()?;
    let phase = reader.read_phase()?;
    let facts = phase.remote_target(
        &g.grant,
        rev(1)?,
        RemoteVerb::List,
        &g.scope.targets[0],
        now()?,
    )?;
    assert_eq!(facts.pending, 1);
    let page = phase.remote_changes(
        &g.grant,
        rev(1)?,
        &g.scope.targets[0],
        ChangeRequest {
            after: before.through.as_ref(),
            limit: 100,
            budget: 65536,
        },
        now()?,
    )?;
    let found=page.changes.iter().any(|c|matches!(&c.kind,ChangeKind::Durable(RemoteDurableEvent::Message {message,..}) if message==&id));
    println!(
        "ordinary inbox has addressed mail, remote pending={}, replay_records={}, cursor_advanced={}",
        facts.pending,
        page.changes.len(),
        page.through != before.through
    );
    phase.close()?;
    d.append(
        f.batch(
            f.self_scope(&f.b).admission,
            None,
            vec![EventBody::MessageRead {
                message: id.clone(),
                recipient: Actor::Agent(f.b.clone()),
            }],
        )?,
        &*l,
    )?;
    let phase = reader.read_phase()?;
    let target = phase.remote_target(
        &g.grant,
        rev(1)?,
        RemoteVerb::List,
        &g.scope.targets[0],
        now()?,
    )?;
    assert_eq!(
        target.pending, 1,
        "another addressed recipient's read must not clear this recipient's pending mail"
    );
    let later = phase.remote_changes(
        &g.grant,
        rev(1)?,
        &g.scope.targets[0],
        ChangeRequest {
            after: page.through.as_ref(),
            limit: 100,
            budget: 65536,
        },
        now()?,
    )?;
    assert!(!later.changes.iter().any(|c|matches!(&c.kind,ChangeKind::Durable(RemoteDurableEvent::Message {message,delivery:RemoteDeliveryState::Read}) if message==&id)),"another recipient's private read must not mark this recipient's shared copy read");
    phase.close()?;
    d.close()?;
    assert!(
        found,
        "authorized shared work mail was visible in the ordinary inbox but silently skipped by remote replay"
    );
    Ok(())
}
