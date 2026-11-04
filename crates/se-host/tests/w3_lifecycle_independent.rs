//! W3 real-host judge (doc 90, black-box) — lifecycle half: revoke and restart.
//!
//! Drives the linked embedded StateEngine host through public surfaces only,
//! with the shared helpers in `support/w3_realhost.rs`.
//!
//! Required inputs: real binaries at `SE_W3_SE_BIN` and `SE_W3_SECODE_SERVER`,
//! the published `SE_W3_NATIVE_DRIVER` and its `SE_W3_PRODUCT_COMMIT`. Missing
//! inputs, setup failures and product errors all fail the test.

use se_store::EventBody;
use secode_stateengine_api as api;

#[path = "support/w3_realhost.rs"]
#[allow(dead_code)]
mod w3_realhost;
use w3_realhost::*;

/// Protects: Owner revocation commits the session transition once and is
/// retryable under its original key; the old grant is fenced and every later
/// call with it is refused by name without any credential; after revocation
/// the agent may bind a replacement.
#[test]
fn revoke_is_retryable_and_fences_the_old_grant_by_name() {
    let judge = Judge::new("revoke").required();
    let opened = judge.open().required();
    let generation = judge.activate(&opened).required();
    let host = opened.host.clone();
    let issued = judge
        .bind(&host, generation, "conv-revoke-1", "judge-bind-4")
        .required();
    let session = issued.session;
    let identity = issued.identity.clone();
    let _ = judge
        .capture(
            &host,
            &session,
            generation,
            "conv-revoke-1",
            api::TurnRole::User,
            "vt-1",
            "judge revoked session turn",
            "judge-capture-11",
        )
        .required();

    let receipt = judge
        .revoke(&host, generation, &identity.session.0, "judge-revoke-1")
        .required();
    let (_commit, revoked) = committed_value(receipt, "revoke").required();
    assert_eq!(
        revoked, identity,
        "the revoke receipt names the revoked identity"
    );

    let retry = judge
        .revoke(&host, generation, &identity.session.0, "judge-revoke-1")
        .required();
    let (_retry_commit, retried) = replayed_value(retry, "revoke retry").required();
    assert_eq!(
        retried, identity,
        "the retryable revocation returns the original identity"
    );

    let fenced_capture = judge.capture(
        &host,
        &session,
        generation,
        "conv-revoke-1",
        api::TurnRole::Assistant,
        "vt-2",
        "judge after revocation",
        "judge-capture-12",
    );
    refusal_contains(
        &fenced_capture
            .err()
            .unwrap_or_else(|| panic!("the fenced grant must be refused")),
        "revoked or replaced",
    )
    .required();

    let fenced_continuity = judge.continuity(&host, &session, generation);
    refusal_contains(
        &fenced_continuity
            .err()
            .unwrap_or_else(|| panic!("the fenced grant must be refused for continuity")),
        "revoked or replaced",
    )
    .required();

    let replacement = judge
        .bind(&host, generation, "conv-revoke-2", "judge-bind-5")
        .required();
    let (_commit2, replacement_identity) =
        committed_value(replacement.receipt.clone(), "replacement bind").required();
    assert_ne!(
        replacement_identity.session.0, identity.session.0,
        "the replacement is a fresh session"
    );

    let old_record = session_record(&judge, generation.0, &identity.session.0).required();
    let reason = body_text(&old_record.current.body, "revoked session").required();
    assert!(
        reason.contains("Replaced"),
        "the revoke reason keeps the end reason: {reason}"
    );

    let receipt = judge.drain_close(&host, generation).required();
    assert!(receipt.writer_flushed, "the drain must flush: {receipt:?}");
}

/// Protects: after drain and close, a fresh generation binds atomically over
/// the previous generation's process-free SE Code session — the old session is
/// revoked in the same committed batch and the replacement names it as
/// incumbent; the old grant is refused by name against the new host; and a
/// live same-generation session is never auto-replaced.
#[test]
fn restart_recovers_only_a_process_free_older_generation_binding() {
    let judge = Judge::new("restart").required();
    let opened = judge.open().required();
    let generation = judge.activate(&opened).required();
    let first = opened.negotiated.generation;
    assert_eq!(first.0, generation.0, "the first host owns generation one");
    let host = opened.host.clone();
    let issued = judge
        .bind(&host, generation, "conv-restart-1", "judge-bind-6")
        .required();
    let old_session = issued.session;
    let old_identity = issued.identity.clone();
    let drain = judge.drain_close(&host, generation).required();
    assert_eq!(drain.generation, first, "the drain names its generation");

    let reopened = judge.open().required();
    assert_eq!(
        reopened.negotiated.generation.0,
        first.0 + 1,
        "the reopened host negotiates the next store generation"
    );
    let second_generation = judge.activate(&reopened).required();
    let second_host = reopened.host.clone();

    let replacement = judge
        .bind(
            &second_host,
            second_generation,
            "conv-restart-2",
            "judge-bind-7",
        )
        .required();
    let (_commit, new_identity) =
        committed_value(replacement.receipt.clone(), "replacement bind").required();
    assert_ne!(
        new_identity.session.0, old_identity.session.0,
        "the restart replacement is a fresh session"
    );

    let old_record =
        session_record(&judge, second_generation.0, &old_identity.session.0).required();
    let reason = body_text(&old_record.current.body, "recovered session").required();
    assert!(
        reason.contains("Previous SE Code host generation ended"),
        "the atomic replacement revokes the old generation by name: {reason}"
    );
    let new_record =
        session_record(&judge, second_generation.0, &new_identity.session.0).required();
    match &new_record.current.body {
        EventBody::SessionActivated {
            incumbent: Some((incumbent, _)),
            ..
        } => {
            assert_eq!(
                incumbent.as_str(),
                old_identity.session.0,
                "the replacement names the replaced session as incumbent"
            );
        }
        other => panic!(
            "the replacement must record the incumbent, got {}",
            body_kind(other)
        ),
    }

    let stale_capture = judge.capture(
        &second_host,
        &old_session,
        second_generation,
        "conv-restart-1",
        api::TurnRole::Assistant,
        "vt-1",
        "judge against a restarted host",
        "judge-capture-13",
    );
    let stale_error = stale_capture
        .err()
        .unwrap_or_else(|| panic!("the old grant must be refused against the new host"));
    let named = refusal_contains(
        &stale_error,
        "grant does not match the original binding and generation",
    )
    .or_else(|_| refusal_contains(&stale_error, "not issued by this host generation"));
    named.required();

    let live = judge.bind(
        &second_host,
        second_generation,
        "conv-restart-3",
        "judge-bind-8",
    );
    refusal_contains(
        &live.err().unwrap_or_else(|| {
            panic!("a live same-generation session must refuse a third binding")
        }),
        "no existing active or prepared session",
    )
    .required();

    let receipt = judge
        .drain_close(&second_host, second_generation)
        .required();
    assert!(receipt.writer_flushed, "the drain must flush: {receipt:?}");
}
