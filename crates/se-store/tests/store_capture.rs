use se_store::*;
use se_types::{Read, SessionId};
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/capture_fixture.rs"]
mod capture_fixture;
use capture_fixture::*;

/// Protects: E3 — natural capture retries retain original turn IDs/receipts after later progress and source rotation.
#[test]
fn capture_replay_after_progress_and_rotation_does_not_rewind_or_duplicate() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let id = session()?;
    let source_id = record()?;
    active(&f, &mut d, &lease, &id, source_id)?;
    let first = d.append(
        capture(&f, &id, source_id, b"first", 0, 1, "vendor-one")?,
        &*lease,
    )?;
    d.append(
        capture(&f, &id, source_id, b"first", 10, 2, "vendor-two")?,
        &*lease,
    )?;
    d.append(
        f.batch(
            f.owner_project(),
            None,
            vec![source(source_id, &id, b"rotated", revision(3)?)],
        )?,
        &*lease,
    )?;
    let head = d.info()?.head;
    let replay = d.append(
        capture(&f, &id, source_id, b"first", 0, 1, "vendor-one")?,
        &*lease,
    )?;
    assert_eq!(replay.state, CommitState::NaturalKeyReplay);
    same_receipt(&first, &replay);
    assert_eq!(d.info()?.head, head);
    let mut snap = d.snapshot(f.self_scope(&f.a))?;
    let projection = present(snap.capture_source(source_id)?)?;
    assert_eq!(projection.revision.value.get(), 4);
    let EventBody::CaptureSource { incarnation, .. } = projection.current.body else {
        return Err("rotation head changed kind".into());
    };
    assert_eq!(incarnation, b"rotated");
    let turns = snap.turns(f.a.clone(), budget(10, 65536, None)?)?;
    assert_eq!(turns.items().len(), 2);
    assert!(
        turns
            .items()
            .iter()
            .any(|e| e.header.event == first.primary_event)
    );
    Ok(())
}

/// Protects: E3 — failure in the cursor member rolls back the turn, its natural identity and the resume head together.
#[test]
fn turn_and_progress_are_one_atomic_effect() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let id = session()?;
    let source_id = record()?;
    active(&f, &mut d, &lease, &id, source_id)?;
    let head = d.info()?.head;
    let error = d
        .append(
            capture(&f, &id, source_id, b"first", 0, 99, "rollback-vendor")?,
            &*lease,
        )
        .err()
        .ok_or("stale progress committed")?;
    assert_eq!(error.code, StoreErrorCode::RevisionConflict);
    assert_eq!(d.info()?.head, head);
    {
        let mut snap = d.snapshot(f.self_scope(&f.a))?;
        assert!(
            snap.turns(f.a.clone(), budget(10, 65536, None)?)?
                .items()
                .is_empty()
        );
        assert_eq!(
            present(snap.capture_source(source_id)?)?
                .revision
                .value
                .get(),
            1
        );
    }
    let good = d.append(
        capture(&f, &id, source_id, b"first", 0, 1, "rollback-vendor")?,
        &*lease,
    )?;
    assert_eq!(good.state, CommitState::Committed);
    let mut snap = d.snapshot(f.self_scope(&f.a))?;
    assert_eq!(
        snap.turns(f.a.clone(), budget(10, 65536, None)?)?
            .items()
            .len(),
        1
    );
    assert_eq!(
        present(snap.capture_source(source_id)?)?
            .revision
            .value
            .get(),
        2
    );
    Ok(())
}

/// Protects: E3 — scoped session/source/turn reads never reveal another agent's capture and retain finite pagination.
#[test]
fn session_source_and_turn_readers_apply_principal_visibility() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let alpha = session()?;
    let beta = session()?;
    let asource = record()?;
    let bsource = record()?;
    active(&f, &mut d, &lease, &alpha, asource)?;
    d.append(
        f.batch(
            f.owner_project(),
            None,
            vec![
                prepared(&f, &beta, &f.b),
                activated(&beta)?,
                source(bsource, &beta, b"beta", Expected::Absent),
            ],
        )?,
        &*lease,
    )?;
    d.append(
        capture(&f, &alpha, asource, b"first", 0, 1, "page-one")?,
        &*lease,
    )?;
    d.append(
        capture(&f, &alpha, asource, b"first", 10, 2, "page-two")?,
        &*lease,
    )?;
    let mut snap = d.snapshot(f.self_scope(&f.a))?;
    let sessions = snap.sessions(budget(10, 65536, None)?)?;
    assert_eq!(sessions.items().len(), 1);
    let EventBody::SessionActivated { session, .. } = &sessions.items()[0].current.body else {
        return Err("active session body absent".into());
    };
    assert_eq!(*session, alpha);
    assert!(snap.session(beta).is_err());
    assert!(snap.capture_source(bsource).is_err());
    assert!(snap.turns(f.b.clone(), budget(10, 65536, None)?).is_err());
    let page = snap.turns(f.a.clone(), budget(1, 65536, None)?)?;
    assert_eq!(page.items().len(), 1);
    let cursor = page.next().ok_or("turn cursor absent")?.clone();
    let next = snap.turns(f.a.clone(), budget(1, 65536, Some(cursor))?)?;
    assert_eq!(next.items().len(), 1);
    assert_ne!(page.items()[0].header.event, next.items()[0].header.event);
    assert!(snap.turns(f.a.clone(), budget(1, 1, None)?).is_err());
    Ok(())
}

/// Protects: E3 — bootstrap hash reads report current credential state, and session end atomically requires revocation first.
#[test]
fn credential_transitions_and_session_end_have_current_revocation_metadata() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let id: SessionId = session()?;
    let credential = record()?;
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros(),
    )?;
    d.append(
        f.batch(
            f.owner_project(),
            None,
            vec![
                prepared(&f, &id, &f.a),
                EventBody::CredentialIssued {
                    credential,
                    session: id.clone(),
                    purpose: "session".into(),
                    secret_sha256: [17; 32],
                    expires_at_us: now + 300_000_000,
                    activation_deadline_us: now + 60_000_000,
                    expected: Expected::Absent,
                },
            ],
        )?,
        &*lease,
    )?;
    let value = present(d.credential([17; 32])?)?;
    assert_eq!(value.state, CredentialState::Prepared);
    assert_eq!(value.agent, f.a);
    assert_eq!(value.session, id);
    assert!(matches!(d.credential([18; 32])?, Read::Absent { .. }));
    assert!(
        d.append(
            f.batch(
                f.owner_project(),
                None,
                vec![EventBody::CredentialActivated {
                    credential,
                    session: id.clone(),
                    expected: revision(1)?,
                    first_request: record()?
                }]
            )?,
            &*lease
        )
        .is_err()
    );
    assert_eq!(
        present(d.credential([17; 32])?)?.state,
        CredentialState::Prepared
    );
    d.append(
        f.batch(
            f.owner_project(),
            None,
            vec![
                activated(&id)?,
                EventBody::CredentialActivated {
                    credential,
                    session: id.clone(),
                    expected: revision(1)?,
                    first_request: record()?,
                },
            ],
        )?,
        &*lease,
    )?;
    assert_eq!(
        present(d.credential([17; 32])?)?.state,
        CredentialState::Active
    );
    let ended = || -> Result<EventBody<InputText>, Box<dyn std::error::Error>> {
        Ok(EventBody::SessionEnded {
            session: id.clone(),
            expected: revision(2)?,
            reason: InputText::Inline("finished".into()),
            final_turn: None,
            final_cursor: None,
        })
    };
    assert!(
        d.append(f.batch(f.owner_project(), None, vec![ended()?])?, &*lease)
            .is_err()
    );
    assert_eq!(
        present(d.credential([17; 32])?)?.state,
        CredentialState::Active
    );
    d.append(
        f.batch(
            f.owner_project(),
            None,
            vec![
                EventBody::CredentialRevoked {
                    credential,
                    expected: revision(2)?,
                    reason: InputText::Inline("session end".into()),
                },
                ended()?,
            ],
        )?,
        &*lease,
    )?;
    let value = present(d.credential([17; 32])?)?;
    assert_eq!(value.state, CredentialState::Revoked);
    assert_eq!(value.revision.value.get(), 3);
    assert_eq!(
        present(d.snapshot(f.self_scope(&f.a))?.session(id)?)?
            .revision
            .value
            .get(),
        3
    );
    Ok(())
}

/// Protects: a reconnect's delivery key cannot change a retained native turn,
/// its original source provenance or the three-event atomic receipt.
#[test]
fn native_capture_replay_preserves_original_source_and_rejects_changed_content() -> Check {
    let f = Fixture::new()?;
    let (mut d, lease) = f.direct()?;
    let id = session()?;
    let source_id = record()?;
    let mut prepared = prepared(&f, &id, &f.a);
    if let EventBody::SessionPrepared { provider, .. } = &mut prepared {
        *provider = Provider::SeCode;
    }
    d.append(
        f.batch(f.owner_project(), None, vec![prepared, activated(&id)?])?,
        &*lease,
    )?;
    let attempt = |key: &str| -> Result<AtomicBatch, Box<dyn std::error::Error>> {
        let mut batch = capture(&f, &id, source_id, b"native-turn", 0, 1, "native-one")?;
        if let EventBody::SessionTurn {
            provider, evidence, ..
        } = &mut batch.events[0].body
        {
            *provider = Provider::SeCode;
            evidence.path = None;
        }
        let source = source(source_id, &id, b"native-turn", Expected::Absent);
        let mut member = f
            .batch(batch.admission.clone(), None, vec![source])?
            .events
            .remove(0);
        member.header.session = Some(id.clone());
        if let EventBody::CaptureSource { native_ref, .. } = &mut member.body {
            *native_ref = serde_json::json!({
                "source_cli":"secode", "conversation":"native-conversation",
                "source_ref":"native-one", "request_key":key,
            })
            .to_string();
        }
        batch.events.insert(0, member);
        Ok(batch)
    };
    let first = d.append(attempt("first-delivery")?, &*lease)?;
    assert_eq!(first.events.len(), 3);
    let head = d.info()?.head;
    for key in ["first-delivery", "reconnect-delivery"] {
        let replay = d.append(attempt(key)?, &*lease)?;
        assert_eq!(replay.state, CommitState::NaturalKeyReplay);
        same_receipt(&first, &replay);
        assert_eq!(d.info()?.head, head);
    }
    for field in ["text", "role", "source"] {
        let mut changed = attempt("changed-delivery")?;
        match field {
            "text" => {
                if let EventBody::SessionTurn { text, .. } = &mut changed.events[1].body {
                    *text = InputText::Inline("different immutable text".into());
                }
            }
            "role" => {
                if let EventBody::SessionTurn { role, .. } = &mut changed.events[1].body {
                    *role = Role::User;
                }
            }
            "source" => {
                if let EventBody::CaptureSource { native_ref, .. } = &mut changed.events[0].body {
                    let mut value: serde_json::Value = serde_json::from_str(native_ref)?;
                    value["source_ref"] = "different native source".into();
                    *native_ref = value.to_string();
                }
            }
            _ => unreachable!(),
        }
        let refused = d
            .append(changed, &*lease)
            .err()
            .ok_or("changed native content replayed")?;
        assert!(matches!(
            refused.code,
            StoreErrorCode::NaturalKeyConflict | StoreErrorCode::RevisionConflict
        ));
        assert_eq!(d.info()?.head, head);
    }
    let mut snap = d.snapshot(f.self_scope(&f.a))?;
    let retained = present(snap.capture_source(source_id)?)?;
    assert_eq!(retained.revision.value.get(), 2);
    let EventBody::CaptureSource { native_ref, .. } =
        retained.original.ok_or("source registration missing")?.body
    else {
        return Err("source registration changed kind".into());
    };
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&native_ref)?["request_key"],
        "first-delivery"
    );
    assert_eq!(
        snap.turns(f.a.clone(), budget(10, 65536, None)?)?
            .items()
            .len(),
        1
    );
    Ok(())
}
