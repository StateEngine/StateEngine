//! Bug: a remote source agent must receive a reply only if it sent to that recipient first, and only while the destination Owner allows it.
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

type R<T> = Result<T, Box<dyn std::error::Error>>;
const SOURCE_HOST: [u8; 32] = [28; 32];

fn rev(n: u64) -> R<Revision> {
    Ok(Revision {
        value: std::num::NonZeroU64::new(n).ok_or("zero revision")?,
    })
}
fn now() -> R<i64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_micros()
        .try_into()?)
}
fn host() -> RemoteHostId {
    RemoteHostId(se_types::Sha256::from_bytes(SOURCE_HOST))
}

struct World {
    f: Fixture,
    d: SqliteDirect,
    l: std::sync::Arc<Lease>,
    reader: SqliteReader,
    session_a: se_types::SessionId,
    session_b: se_types::SessionId,
}

fn grant(f: &Fixture, n: u8, targets: Vec<RemoteTarget>) -> R<GrantRecord> {
    let at = now()?;
    Ok(GrantRecord {
        grant: RemoteGrantId::from_parts(1_700_000_000_000, [n; 10])?,
        principal: RemotePrincipalId::from_parts(1_700_000_000_000, [n + 1; 10])?,
        device: RemoteDeviceId::from_parts(1_700_000_000_000, [n + 2; 10])?,
        credential_sha256: CredentialDigest([n + 3; 32]),
        host: RemoteHostId(se_types::Sha256::from_bytes([22; 32])),
        store: f.store.clone(),
        subject: RemoteSubject::Machine { host: host() },
        scope: RemoteScope {
            targets,
            verbs: vec![RemoteVerb::List, RemoteVerb::Watch, RemoteVerb::Send],
        },
        issued_at_us: at,
        last_use_at_us: at,
        expires_at_us: at + GRANT_INACTIVITY_US,
        authority_revision: rev(1)?,
        lease_revision: rev(1)?,
        state: GrantState::Active,
    })
}
fn connect(w: &mut World, g: &GrantRecord, key: &str) -> R<()> {
    w.d.append(
        w.f.batch(
            w.f.admission(Scope::Registry, Actor::Human(w.f.owner.clone())),
            Some(request(key)?),
            vec![EventBody::RemoteSecurity {
                transition: SecurityTransition::Connect {
                    grant: Box::new(g.clone()),
                },
            }],
        )?,
        &*w.l,
    )?;
    Ok(())
}
fn world() -> R<(World, Vec<RemoteTarget>)> {
    let f = Fixture::new()?;
    let (mut d, l) = f.direct()?;
    let mut sessions = Vec::new();
    for agent in [&f.a, &f.b] {
        let session = capture::session()?;
        d.append(
            f.batch(
                f.owner_project(),
                Some(request(&format!("session-{}", agent.as_str()))?),
                vec![
                    capture::prepared(&f, &session, agent),
                    capture::activated(&session)?,
                ],
            )?,
            &*l,
        )?;
        sessions.push(session);
    }
    let reader = present(SqliteFactory::open_reader(&f.options)?)?;
    let targets = [&f.a, &f.b]
        .iter()
        .map(|a| RemoteTarget {
            project: f.project.clone(),
            agent: (*a).clone(),
        })
        .collect();
    let session_b = sessions.pop().ok_or("session")?;
    let session_a = sessions.pop().ok_or("session")?;
    Ok((
        World {
            f,
            d,
            l,
            reader,
            session_a,
            session_b,
        },
        targets,
    ))
}
fn source(agent: &se_types::AgentId, project: &se_types::ProjectId) -> R<RemoteSourceSession> {
    Ok(RemoteSourceSession {
        host: host(),
        project: project.clone(),
        agent: agent.clone(),
        session: capture::session()?,
        generation: se_types::Generation::new(1)?,
    })
}
/// The authenticated source sends one message to `target` through grant `g`.
fn remote_send(
    w: &mut World,
    g: &GrantRecord,
    src: &RemoteSourceSession,
    target: &RemoteTarget,
    session: &se_types::SessionId,
    key: &str,
) -> R<se_types::MessageId> {
    let id = message()?;
    let send = RemoteSend {
        target: target.clone(),
        session: session.clone(),
        body: se_types::Body::new("hello from the remote source")?,
        idempotency_key: IdempotencyKey::new(key)?,
    };
    let admission = se_core::remote::authorize(
        g.clone(),
        RemoteVerb::Send,
        std::slice::from_ref(target),
        now()?,
    )?;
    let batch = se_core::remote::plan_send(
        admission,
        send,
        RemoteAttribution {
            host: g.host,
            store: g.store.clone(),
            principal: g.principal.clone(),
            grant: g.grant.clone(),
            device: g.device.clone(),
            authority_revision: 1,
            source: Some(src.clone()),
        },
        se_core::remote::RemoteSendFacts {
            store: w.reader.info()?,
            generation: 1,
            occurred_at_us: now()?,
            message: id.clone(),
            sent_event: event()?,
            attribution_event: event()?,
        },
    )?;
    w.d.append(batch, &*w.l)?;
    Ok(id)
}
/// An ordinary agent message to a remote principal, committed under its native session.
fn agent_message(
    w: &mut World,
    agent: &se_types::AgentId,
    session: &se_types::SessionId,
    to: &RemotePrincipalId,
    original: Option<&se_types::MessageId>,
    key: &str,
) -> R<CommitReceipt> {
    let mut admission = w.f.admission(
        Scope::Project(w.f.project.clone()),
        Actor::Agent(agent.clone()),
    );
    admission.session = Some(session.clone());
    let mut batch = w.f.batch(
        admission,
        Some(request(key)?),
        vec![EventBody::MessageSent {
            quiet: false,
            message: message()?,
            recipient: Actor::Remote(to.clone()),
            kind: "note".into(),
            body: InputText::Inline("reply body".into()),
            refs: vec![],
            reply_to: original.cloned(),
        }],
    )?;
    for event in &mut batch.events {
        event.header.session = Some(session.clone());
    }
    Ok(w.d.append(batch, &*w.l)?)
}
fn queued(
    w: &World,
    g: &GrantRecord,
    src: &RemoteSourceSession,
    target: &RemoteTarget,
) -> R<usize> {
    let phase = w.reader.read_phase()?;
    let page = phase.remote_replies(ReplyQuery {
        grant_id: &g.grant,
        revision: g.authority_revision,
        source: src,
        target,
        after: None,
        limit: 20,
        now: now()?,
    });
    phase.close()?;
    Ok(page?.messages.len())
}
fn set_permission(
    w: &mut World,
    address: &RemoteAgentAddress,
    allowed: bool,
    expected: Option<Revision>,
    key: &str,
) -> R<()> {
    w.d.append(
        w.f.batch(
            w.f.admission(Scope::Registry, Actor::Human(w.f.owner.clone())),
            Some(request(key)?),
            vec![EventBody::RemoteSecurity {
                transition: SecurityTransition::SourcePermission {
                    address: address.clone(),
                    allowed,
                    expected,
                },
            }],
        )?,
        &*w.l,
    )?;
    Ok(())
}

/// Bug: a reply queued for a source must still be delivered after the source reconnects under a renewed machine grant.
#[test]
fn reply_to_source_that_sent_first_is_delivered_after_reconnect() -> Check {
    let (mut w, targets) = world()?;
    let target = targets[0].clone();
    let g1 = grant(&w.f, 40, targets.clone())?;
    connect(&mut w, &g1, "connect-1")?;
    let x = source(&w.f.b.clone(), &w.f.project.clone())?;
    let s0 = w.session_a.clone();
    let original = remote_send(&mut w, &g1, &x, &target, &s0, "first")?;
    let (a, sa) = (w.f.a.clone(), w.session_a.clone());
    agent_message(&mut w, &a, &sa, &g1.principal, Some(&original), "reply-1")?;
    // The source machine disconnects and later returns under a renewed grant.
    let g2 = grant(&w.f, 50, targets)?;
    connect(&mut w, &g2, "connect-2")?;
    let n = queued(&w, &g2, &x, &target)?;
    w.d.close()?;
    assert_eq!(n, 1, "queued reply was not delivered after reconnection");
    Ok(())
}

/// Bug: a reply must be refused unless the replying agent received that source's own message.
#[test]
fn reply_to_never_contacted_source_is_refused() -> Check {
    let (mut w, targets) = world()?;
    let (ta, tb) = (targets[0].clone(), targets[1].clone());
    let g1 = grant(&w.f, 40, targets.clone())?;
    let g2 = grant(&w.f, 50, targets)?;
    connect(&mut w, &g1, "connect-1")?;
    connect(&mut w, &g2, "connect-2")?;
    let x = source(&w.f.b.clone(), &w.f.project.clone())?;
    let z = source(&w.f.a.clone(), &w.f.project.clone())?;
    // X wrote only to agent A. Z wrote only to agent B.
    let (s0, s1) = (w.session_a.clone(), w.session_b.clone());
    let to_a = remote_send(&mut w, &g1, &x, &ta, &s0, "x-to-a")?;
    let to_b = remote_send(&mut w, &g2, &z, &tb, &s1, "z-to-b")?;
    let (a, sa) = (w.f.a.clone(), w.session_a.clone());
    let (b, sb) = (w.f.b.clone(), w.session_b.clone());
    // A never received mail from Z: Z's principal with Z's message id.
    assert!(agent_message(&mut w, &a, &sa, &g2.principal, Some(&to_b), "a-to-z").is_err());
    // A cites its own contact's message but addresses the other principal.
    assert!(agent_message(&mut w, &a, &sa, &g2.principal, Some(&to_a), "a-to-z-via-x").is_err());
    // B did not receive X's message, so it cannot answer it.
    assert!(agent_message(&mut w, &b, &sb, &g1.principal, Some(&to_a), "b-to-x").is_err());
    // A message with no original cannot create a route at all.
    assert!(agent_message(&mut w, &a, &sa, &g1.principal, None, "a-cold").is_err());
    assert_eq!(queued(&w, &g1, &x, &ta)?, 0);
    assert_eq!(queued(&w, &g2, &z, &tb)?, 0);
    // The exact recipient can answer its own contact.
    agent_message(&mut w, &a, &sa, &g1.principal, Some(&to_a), "a-to-x")?;
    assert_eq!(queued(&w, &g1, &x, &ta)?, 1);
    w.d.close()?;
    Ok(())
}

/// Bug: revoking a source must stop delivery of its already queued replies and of any new reply or message from it.
#[test]
fn revoked_source_gets_no_queued_reply_and_cannot_send() -> Check {
    let (mut w, targets) = world()?;
    let target = targets[0].clone();
    let g1 = grant(&w.f, 40, targets)?;
    connect(&mut w, &g1, "connect-1")?;
    let x = source(&w.f.b.clone(), &w.f.project.clone())?;
    let s0 = w.session_a.clone();
    let original = remote_send(&mut w, &g1, &x, &target, &s0, "first")?;
    let (a, sa) = (w.f.a.clone(), w.session_a.clone());
    agent_message(&mut w, &a, &sa, &g1.principal, Some(&original), "reply-1")?;
    assert_eq!(queued(&w, &g1, &x, &target)?, 1);
    set_permission(&mut w, &x.address(), false, None, "revoke-x")?;
    assert!(
        queued(&w, &g1, &x, &target).is_err(),
        "queued reply was delivered to a revoked source"
    );
    assert!(
        agent_message(&mut w, &a, &sa, &g1.principal, Some(&original), "reply-2").is_err(),
        "a new reply was queued for a revoked source"
    );
    assert!(
        remote_send(&mut w, &g1, &x, &target, &sa, "second").is_err(),
        "a revoked source could still send"
    );
    // A different source on the same machine grant keeps its legacy access.
    let other = source(&w.f.a.clone(), &w.f.project.clone())?;
    remote_send(&mut w, &g1, &other, &target, &sa, "other-source")?;
    w.d.close()?;
    Ok(())
}

fn inbox(w: &World, full: bool) -> R<se_core::ops::outputs::MessagePage> {
    let scope = w.f.self_scope(&w.f.a);
    let mut snapshot = w.reader.snapshot(scope.clone())?;
    let output = se_core::ops::message::list(
        se_core::ops::inputs::MessageList {
            cli_list: false,
            view: se_core::ops::inputs::MessageView::All,
            mailbox: se_core::ops::inputs::MessageBox::Inbox,
            from: None,
            kind: None,
            full,
            limit: 100,
            preview_chars: Some(3),
            cursor: None,
            owner_to: None,
        },
        &mut se_core::commit::Cx {
            read: &mut snapshot,
            admission: &scope.admission,
        },
    );
    snapshot.close()?;
    Ok(output?)
}

/// One delegated principal can speak for several sources; each row retains its own route.
#[test]
fn inbox_keeps_distinct_sources_and_reply_ids_for_one_remote_principal() -> Check {
    let (mut w, targets) = world()?;
    let target = targets[0].clone();
    let g = grant(&w.f, 40, targets)?;
    connect(&mut w, &g, "connect-page")?;
    let sa = w.session_a.clone();
    let x = source(&w.f.a, &w.f.project)?;
    let z = source(&w.f.b, &w.f.project)?;
    let first = remote_send(&mut w, &g, &x, &target, &sa, "source-x")?;
    let second = remote_send(&mut w, &g, &z, &target, &sa, "source-z")?;
    let head = w.d.info()?.head;
    for full in [false, true] {
        let output = inbox(&w, full)?;
        assert_eq!(output.unread_total, Some(2));
        assert_eq!(output.page.items().len(), 2);
        for (id, address) in [(&first, x.address()), (&second, z.address())] {
            let row = output
                .page
                .items()
                .iter()
                .find(|row| &row.id == id)
                .ok_or("row missing")?;
            assert_eq!(row.from.kind, "remote_agent");
            assert_eq!(row.from.id, address.selector());
            let reply = row.remote_reply.as_ref().ok_or("reply route missing")?;
            assert_eq!(reply.to, address.selector());
            assert_eq!(&reply.reply_to, id);
            assert_eq!(row.to.id, w.f.a.as_str());
            assert_eq!(row.disposition.state, "unread");
            assert_eq!(row.body.bytes, "hello from the remote source".len() as u64);
            assert_eq!(row.body.complete, full);
            assert_eq!(
                row.body.text,
                if full {
                    "hello from the remote source"
                } else {
                    "hel"
                }
            );
        }
        assert_eq!(w.d.info()?.head, head, "listing mutated mail");
    }
    let a = w.f.a.clone();
    agent_message(&mut w, &a, &sa, &g.principal, Some(&first), "answer-x")?;
    agent_message(&mut w, &a, &sa, &g.principal, Some(&second), "answer-z")?;
    assert_eq!(queued(&w, &g, &x, &target)?, 1);
    assert_eq!(queued(&w, &g, &z, &target)?, 1);
    assert_eq!(inbox(&w, true)?.unread_total, Some(2));
    w.d.close()?;
    Ok(())
}

/// Repeated local actors are resolved afresh on the next read, without marking mail read.
#[test]
fn inbox_local_names_refresh_between_reads_without_changing_unread_mail() -> Check {
    let (mut w, _) = world()?;
    for n in 0..24 {
        w.d.append(
            w.f.send(
                Actor::Agent(w.f.b.clone()),
                Actor::Agent(w.f.a.clone()),
                message()?,
                "é🦀mail",
                &format!("local-{n}"),
            )?,
            &*w.l,
        )?;
    }
    let head = w.d.info()?.head;
    let first = inbox(&w, false)?;
    assert_eq!(first.unread_total, Some(24));
    assert_eq!(first.page.items().len(), 24);
    for row in first.page.items() {
        assert_eq!(row.from.name, "Juniper");
        assert_eq!(row.body.text, "é🦀m");
        assert_eq!(row.body.bytes, "é🦀mail".len() as u64);
        assert_eq!(row.disposition.state, "unread");
    }
    assert_eq!(w.d.info()?.head, head);
    w.d.append(
        w.f.batch(
            w.f.owner_project(),
            Some(request("rename-sender")?),
            vec![EventBody::PrincipalRenamed {
                principal: Actor::Agent(w.f.b.clone()),
                name: "Updated sender".into(),
                expected: revision(1)?,
            }],
        )?,
        &*w.l,
    )?;
    let head = w.d.info()?.head;
    let second = inbox(&w, true)?;
    assert_eq!(second.unread_total, Some(24));
    assert_eq!(
        first.page.items().iter().map(|r| &r.id).collect::<Vec<_>>(),
        second
            .page
            .items()
            .iter()
            .map(|r| &r.id)
            .collect::<Vec<_>>()
    );
    for row in second.page.items() {
        assert_eq!(row.from.name, "Updated sender");
        assert_eq!(row.disposition.state, "unread");
        assert_eq!(row.body.text, "é🦀mail");
        assert!(row.body.complete);
    }
    assert_eq!(w.d.info()?.head, head);
    w.d.close()?;
    Ok(())
}

/// Return-mail attribution must win over the generic delegated-principal identity.
#[test]
fn inbox_resolves_return_mail_per_message_and_retains_its_reply_route() -> Check {
    let (mut w, targets) = world()?;
    let g = grant(&w.f, 40, targets.clone())?;
    connect(&mut w, &g, "connect-return-page")?;
    let local = RemoteAgentAddress {
        host: RemoteHostId(se_types::Sha256::from_bytes([90; 32])),
        project: w.f.project.clone(),
        agent: w.f.a.clone(),
    };
    let mut expected = Vec::new();
    for (n, target) in targets.into_iter().enumerate() {
        let original = message()?;
        let pending = PendingContact {
            source: local.clone(),
            peer: host(),
            target: target.clone(),
            alias: "peer".into(),
            request_key: IdempotencyKey::new(format!("contact-{n}"))?,
            original_grant: g.grant.clone(),
            local_reply: None,
        };
        let contact = MailContact {
            source: local.clone(),
            peer: pending.peer,
            target: target.clone(),
            original: original.clone(),
            principal: g.principal.clone(),
            alias: pending.alias.clone(),
            request_key: pending.request_key.clone(),
            original_grant: pending.original_grant.clone(),
            local_reply: None,
        };
        let mut admission = w.f.admission(
            Scope::Project(w.f.project.clone()),
            Actor::Agent(w.f.a.clone()),
        );
        admission.session = Some(w.session_a.clone());
        let mut batch = w.f.batch(
            admission,
            Some(request(&format!("contact-write-{n}"))?),
            vec![
                EventBody::RemoteMailboxRecorded {
                    change: MailboxChange::Pending { record: pending },
                },
                EventBody::RemoteMailboxRecorded {
                    change: MailboxChange::Contact { record: contact },
                },
            ],
        )?;
        for e in &mut batch.events {
            e.header.door = Door::Host;
            e.header.session = Some(w.session_a.clone());
        }
        w.d.append(batch, &*w.l)?;
        let id = message()?;
        let sender = RemoteAgentAddress {
            host: host(),
            project: target.project.clone(),
            agent: target.agent.clone(),
        };
        let mut batch = w.f.batch(
            w.f.admission(
                Scope::Project(w.f.project.clone()),
                Actor::Remote(g.principal.clone()),
            ),
            Some(request(&format!("receive-{n}"))?),
            vec![
                EventBody::MessageSent {
                    quiet: true,
                    message: id.clone(),
                    recipient: Actor::Agent(w.f.a.clone()),
                    kind: "note".into(),
                    body: InputText::Inline(format!("return-{n}")),
                    refs: vec![],
                    reply_to: None,
                },
                EventBody::RemoteMailboxRecorded {
                    change: MailboxChange::Received {
                        record: ReturnAttribution {
                            message: id.clone(),
                            peer_message: message()?,
                            original,
                            source: local.clone(),
                            sender: sender.clone(),
                            principal: g.principal.clone(),
                        },
                    },
                },
                EventBody::RemoteMailboxRecorded {
                    change: MailboxChange::Checkpoint {
                        source: local.clone(),
                        peer: host(),
                        target,
                        grant: g.grant.clone(),
                        cursor: se_types::Cursor::new(format!("return-cursor-{n}"))?,
                    },
                },
            ],
        )?;
        for e in &mut batch.events {
            e.header.door = Door::Host;
        }
        w.d.append(batch, &*w.l)?;
        expected.push((id, sender));
    }
    let head = w.d.info()?.head;
    let output = inbox(&w, true)?;
    assert_eq!(output.unread_total, Some(2));
    assert_eq!(output.page.items().len(), 2);
    for (id, sender) in expected {
        let row = output
            .page
            .items()
            .iter()
            .find(|r| r.id == id)
            .ok_or("return row missing")?;
        assert_eq!(row.from.kind, "remote_agent");
        assert_eq!(row.from.id, sender.selector());
        let reply = row.remote_reply.as_ref().ok_or("return reply missing")?;
        assert_eq!(reply.to, sender.selector());
        assert_eq!(reply.reply_to, id);
        assert_eq!(row.disposition.state, "unread");
    }
    assert_eq!(w.d.info()?.head, head);
    w.d.close()?;
    Ok(())
}
