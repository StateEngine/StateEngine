use se_store::*;
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/capture_fixture.rs"]
#[allow(
    dead_code,
    reason = "Failure cases share typed session/source fixtures."
)]
mod capture_fixture;

/// Protects: store reference failures — unknown message identifiers are a missing-reference refusal naming the identifier, never unreadable storage.
#[test]
fn unknown_message_mark_is_not_unreadable_storage() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let id = message()?;
    let error = direct
        .append(
            f.batch(
                f.owner_project(),
                None,
                vec![EventBody::MessageRead {
                    message: id.clone(),
                    recipient: Actor::Human(f.owner.clone()),
                }],
            )?,
            &*lease,
        )
        .err()
        .ok_or("unknown message mark committed")?;
    assert_eq!(error.code, StoreErrorCode::ReferenceMissing);
    assert!(
        error.cause.contains(id.as_str()),
        "missing-reference refusal omitted the caller's identifier: {error}"
    );
    Ok(())
}

/// Protects: store reference failures — a capture against an unknown source refuses as not-found and rolls back its turn/progress together.
#[test]
fn unknown_capture_source_is_not_unreadable_storage() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let sid = capture_fixture::session()?;
    let source = capture_fixture::record()?;
    direct.append(
        f.batch(
            f.owner_project(),
            Some(request(&format!("fixture-store_failures-48-{}", serial()))?),
            vec![
                capture_fixture::prepared(&f, &sid, &f.a),
                capture_fixture::activated(&sid)?,
            ],
        )?,
        &*lease,
    )?;
    let head = direct.info()?.head;
    let error = direct
        .append(
            capture_fixture::capture(&f, &sid, source, b"first", 0, 1, "absent-source")?,
            &*lease,
        )
        .err()
        .ok_or("unknown capture source committed")?;
    assert_eq!(error.code, StoreErrorCode::ReferenceMissing);
    assert!(
        error.cause.replace('-', "").to_ascii_lowercase().contains(
            &source
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ),
        "missing-reference refusal omitted the source id: {error}"
    );
    assert_eq!(direct.info()?.head, head);
    Ok(())
}

/// Protects: store marker scope — a real message addressed to B cannot be marked by A naming itself as recipient, and that refusal names the message rather than unreadable storage.
#[test]
fn marker_for_another_recipient_is_a_scoped_reference_refusal() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let id = message()?;
    direct.append(
        f.send(
            Actor::Agent(f.a.clone()),
            Actor::Agent(f.b.clone()),
            id.clone(),
            "for B",
            "recipient-setup",
        )?,
        &*lease,
    )?;
    let head = direct.info()?.head;
    let error = direct
        .append(
            f.batch(
                f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone())),
                None,
                vec![EventBody::MessageRead {
                    message: id.clone(),
                    recipient: Actor::Agent(f.a.clone()),
                }],
            )?,
            &*lease,
        )
        .err()
        .ok_or("foreign-recipient marker committed")?;
    assert!(
        matches!(
            error.code,
            StoreErrorCode::ReferenceMissing | StoreErrorCode::ScopeMismatch
        ),
        "recipient mismatch became unreadable storage: {error}"
    );
    assert!(
        error.cause.contains(id.as_str()),
        "recipient refusal omitted the message id: {error}"
    );
    assert_eq!(direct.info()?.head, head);
    Ok(())
}

#[cfg(target_os = "linux")]
#[path = "support/store_faults.rs"]
mod native_faults;
