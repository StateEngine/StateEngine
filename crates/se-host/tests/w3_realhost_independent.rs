//! W3 real-host judge (doc 90, black-box).
//!
//! Drives the linked embedded StateEngine host through public surfaces only:
//! the `se` CLI for trusted setup and public event readback, the public
//! `secode_stateengine_api` `HostFactory`/`Host` over `se_host::embedded_factory`,
//! and independent public reads of the Rust store as the bound agent. The native
//! task consumer additionally invokes the published SE Code driver with a fresh
//! judge nonce and verifies its real file effects and public durable captures.
//!
//! Required inputs: real binaries at `SE_W3_SE_BIN` and `SE_W3_SECODE_SERVER`,
//! the published `SE_W3_NATIVE_DRIVER` and its `SE_W3_PRODUCT_COMMIT`. Missing
//! inputs, setup failures and product errors all fail the test.

use se_store::{EventBody, Snapshot, StoredEvent, StoredText};
use secode_stateengine_api as api;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

#[path = "support/w3_timestamp_replay.rs"]
mod timestamp_replay;
#[path = "support/w3_realhost.rs"]
#[allow(dead_code)]
mod w3_realhost;
use w3_realhost::*;
// ---------------------------------------------------------------- tests

/// Protects: a cold embedded open over a home without the trusted setup
/// reports the setup-required refusal by name, and a home prepared through
/// `se init` opens with its real store facts before any activation.
#[test]
fn open_refuses_an_uninitialized_home_by_name() {
    let helper = match require_se() {
        Ok(path) => path,
        Err(()) => missing_helper(),
    };
    let root = judge_root("open");
    let empty = root.join("home");
    std::fs::create_dir_all(&empty).required();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o700)).required();
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .required();
    let factory = se_host::embedded_factory(runtime.handle().clone());
    let config = api::HostConfig {
        state_home: empty.clone(),
        helper_executable: helper.clone(),
        linux_delegation: api::LinuxDelegation::AutoUserManager,
        api: api::API_VERSION,
        kind: api::HostKind::EmbeddedSecode,
        features: vec![api::Feature::LocalListener],
        limits: api::Limits {
            page_items: std::num::NonZeroU32::new(100).ok_or_missing(),
            payload_bytes: std::num::NonZeroU32::new(256 * 1024).ok_or_missing(),
            notice_ids: std::num::NonZeroU32::new(100).ok_or_missing(),
        },
    };
    let options = api::OpenOptions {
        expected_generation: None,
        timeout: Duration::from_secs(10),
        cancellation: Arc::new(NoopCancellation),
    };
    let opened = runtime.block_on(factory.open(config, options)).required();
    let kind = api_read_kind(&opened);
    let checked = match opened {
        api::Read::Absent { checked } => checked,
        _ => panic!("an uninitialized home must open Absent, got {kind}"),
    };
    assert!(
        checked.contains("setup-required"),
        "the refusal must name the setup requirement: {checked}"
    );
    assert!(
        checked.contains("se init"),
        "the refusal must name the trusted setup flow: {checked}"
    );

    let (home, _project, _agent) = init_project(&helper, &root).required();
    let config = api::HostConfig {
        state_home: home.clone(),
        helper_executable: helper.clone(),
        linux_delegation: api::LinuxDelegation::AutoUserManager,
        api: api::API_VERSION,
        kind: api::HostKind::EmbeddedSecode,
        features: vec![api::Feature::LocalListener],
        limits: api::Limits {
            page_items: std::num::NonZeroU32::new(100).ok_or_missing(),
            payload_bytes: std::num::NonZeroU32::new(256 * 1024).ok_or_missing(),
            notice_ids: std::num::NonZeroU32::new(100).ok_or_missing(),
        },
    };
    let options = api::OpenOptions {
        expected_generation: None,
        timeout: Duration::from_secs(10),
        cancellation: Arc::new(NoopCancellation),
    };
    let factory = se_host::embedded_factory(runtime.handle().clone());
    let opened = runtime.block_on(factory.open(config, options)).required();
    let kind = api_read_kind(&opened);
    let opened = match opened {
        api::Read::Present { value } => value,
        _ => panic!("an initialized home must open Present, got {kind}"),
    };
    assert_eq!(
        opened.negotiated.api,
        api::API_VERSION,
        "the negotiated API must be the linked major"
    );
    assert_eq!(
        opened.store.version.application_id, 0x5345_4E47,
        "the store readback must carry the StateEngine application id"
    );
    assert!(
        opened
            .negotiated
            .features
            .contains(&api::Feature::LocalListener),
        "the embedded host offers its local listener"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// Protects: one Owner bind commits a fresh SE Code session exactly once; the
/// original key and intent replay to the original committed identity with a
/// single prepared/activated store pair; and a second binding for the same
/// agent is refused by name until the first is revoked.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn bind_commits_once_and_replays_the_original_identity() {
    let judge = Judge::new("bind").required();
    let opened = judge.open().required();
    let generation = judge.activate(&opened).required();
    let host = opened.host.clone();

    let issued = judge
        .bind(&host, generation, "conv-bind-1", "judge-bind-1")
        .required();
    let (commit, identity) = committed_value(issued.receipt.clone(), "bind").required();
    assert_eq!(
        commit.idempotency_key.0, "judge-bind-1",
        "the receipt carries the original key"
    );
    assert_eq!(
        identity.project.0, judge.project,
        "the identity names the bound project"
    );
    assert_eq!(
        identity.agent.0, judge.agent,
        "the identity names the bound agent"
    );
    assert!(
        identity.session.0.starts_with("ses_") && identity.session.0.len() == 40,
        "the session is a fresh canonical id: {:?}",
        identity.session.0
    );
    assert_eq!(
        issued.session.identity,
        identity.clone(),
        "the issued grant carries the committed identity"
    );

    let replay = judge
        .bind(&host, generation, "conv-bind-1", "judge-bind-1")
        .required();
    let (replay_commit, replay_identity) = replayed_value(replay.receipt, "bind replay").required();
    assert_eq!(
        replay_identity, identity,
        "the replay returns the original committed identity"
    );
    assert_eq!(
        replay_commit.event, commit.event,
        "the replay names the original committed event"
    );

    let record = session_record(&judge, generation.0, &identity.session.0).required();
    match &record.current.body {
        EventBody::SessionActivated { session, .. } => {
            assert_eq!(
                session.as_str(),
                identity.session.0,
                "the store head is the activated session"
            )
        }
        other => panic!(
            "the store head must be SessionActivated, got {}",
            body_kind(other)
        ),
    }
    let prepared = record.original.as_deref().unwrap_or(&record.current);
    match &prepared.body {
        EventBody::SessionPrepared {
            provider,
            consent,
            native_ref,
            generation: written,
            ..
        } => {
            assert_eq!(
                *provider,
                se_store::Provider::SeCode,
                "the session is prepared for SE Code"
            );
            assert_eq!(
                *consent,
                se_store::Consent::Capture,
                "capture consent is recorded"
            );
            assert_eq!(
                native_ref.as_str(),
                "conv-bind-1",
                "the native conversation is recorded"
            );
            assert_eq!(
                *written, generation.0,
                "the preparation carries the host generation"
            );
        }
        other => panic!(
            "the original must be SessionPrepared, got {}",
            body_kind(other)
        ),
    }
    assert_eq!(
        record.revision.value.get(),
        2,
        "one prepared and one activated event, nothing else"
    );

    let second = judge.bind(&host, generation, "conv-bind-2", "judge-bind-2");
    let second_error = second
        .err()
        .unwrap_or_else(|| panic!("a second live binding for the same agent must be refused"));
    refusal_contains(&second_error, "no existing active or prepared session").required();

    let receipt = judge.drain_close(&host, generation).required();
    assert!(
        receipt.writer_flushed && receipt.unresolved_effects == 0,
        "the drain must report a flushed writer: {receipt:?}"
    );
}

/// Protects: native turn capture commits the exact canonical text with a
/// matching SHA-256 and no invented transcript path; the same natural key
/// replays to the original committed turn; a mismatched digest or a foreign
/// conversation is refused by name; continuity reads the captured turns back
/// under the bound identity; and the public history shows both turns with the
/// app-server provenance.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn capture_replays_by_natural_key_without_inventing_a_transcript_path() {
    let judge = Judge::new("capture").required();
    let opened = judge.open().required();
    let generation = judge.activate(&opened).required();
    let host = opened.host.clone();
    let issued = judge
        .bind(&host, generation, "conv-capture-1", "judge-bind-3")
        .required();
    let session = issued.session;

    let user_text = "judge user turn: π and café";
    let assistant_text = "judge assistant turn";
    let user_receipt = judge
        .capture(
            &host,
            &session,
            generation,
            "conv-capture-1",
            api::TurnRole::User,
            "vt-1",
            user_text,
            "judge-capture-1",
        )
        .required();
    let (user_commit, user_event) = committed_value(user_receipt, "user capture").required();
    let assistant_receipt = judge
        .capture(
            &host,
            &session,
            generation,
            "conv-capture-1",
            api::TurnRole::Assistant,
            "vt-2",
            assistant_text,
            "judge-capture-2",
        )
        .required();
    let (_assistant_commit, assistant_event) =
        committed_value(assistant_receipt, "assistant capture").required();
    assert_ne!(
        user_event.id.0, assistant_event.id.0,
        "each capture commits its own turn event"
    );

    let replay = judge
        .capture(
            &host,
            &session,
            generation,
            "conv-capture-1",
            api::TurnRole::User,
            "vt-1",
            user_text,
            "judge-capture-1",
        )
        .required();
    let (replay_commit, replay_event) = replayed_value(replay, "capture replay").required();
    assert_eq!(
        replay_event, user_event,
        "the natural replay returns the original committed turn"
    );
    assert_eq!(
        replay_commit.event, user_commit.event,
        "the replay names the original event position"
    );

    let natural_replay = judge
        .capture(
            &host,
            &session,
            generation,
            "conv-capture-1",
            api::TurnRole::User,
            "vt-1",
            user_text,
            "judge-capture-distinct-key",
        )
        .required();
    let (natural_commit, natural_event) =
        replayed_value(natural_replay, "distinct-key natural replay").required();
    assert_eq!(
        natural_event, user_event,
        "natural identity replays despite a distinct request key"
    );
    assert_eq!(
        natural_commit.event, user_commit.event,
        "natural replay preserves the first committed event"
    );

    let bad_digest = judge.capture_with(
        &host,
        &session,
        generation,
        api::CapturedTurn {
            conversation: api::ProviderSessionId("conv-capture-1".into()),
            vendor_turn: "vt-9".into(),
            vendor_event: Some("evt-vt-9".into()),
            machine_id: None,
            source_ref: Some("secode-event:vt-9".into()),
            source_cli: "secode".into(),
            nesting: None,
            role: api::TurnRole::User,
            occurred_at: api::UnixMicros(now_micros()),
            content: api::BoundedText {
                text: "judge user turn".into(),
                utf8_bytes: "judge user turn".len() as u64,
                complete: true,
                omitted_bytes: Some(0),
            },
            source_sha256: api::Sha256([7; 32]),
            idempotency_key: api::IdempotencyKey("judge-capture-9".into()),
        },
    );
    refusal_contains(
        &bad_digest
            .err()
            .unwrap_or_else(|| panic!("a mismatched digest must be refused")),
        "SHA-256 of the exact canonical text",
    )
    .required();

    let foreign = judge.capture_with(
        &host,
        &session,
        generation,
        api::CapturedTurn {
            conversation: api::ProviderSessionId("conv-other".into()),
            vendor_turn: "vt-10".into(),
            vendor_event: Some("evt-vt-10".into()),
            machine_id: None,
            source_ref: Some("secode-event:vt-10".into()),
            source_cli: "secode".into(),
            nesting: None,
            role: api::TurnRole::User,
            occurred_at: api::UnixMicros(now_micros()),
            content: api::BoundedText {
                text: "judge foreign conversation".into(),
                utf8_bytes: "judge foreign conversation".len() as u64,
                complete: true,
                omitted_bytes: Some(0),
            },
            source_sha256: api::Sha256(
                Sha256::digest("judge foreign conversation".as_bytes()).into(),
            ),
            idempotency_key: api::IdempotencyKey("judge-capture-10".into()),
        },
    );
    refusal_contains(
        &foreign
            .err()
            .unwrap_or_else(|| panic!("a foreign conversation must be refused")),
        "original bound generation and provider conversation",
    )
    .required();

    let rows = turn_rows(&judge, generation.0).required();
    let turns: Vec<&StoredEvent> = rows
        .iter()
        .filter(|row| matches!(row.body, EventBody::SessionTurn { .. }))
        .collect();
    assert_eq!(
        turns.len(),
        2,
        "exactly two captured turns exist in the store"
    );
    for (role, vendor, text, digest) in [
        (
            "user",
            "vt-1",
            user_text,
            Sha256::digest(user_text.as_bytes()),
        ),
        (
            "assistant",
            "vt-2",
            assistant_text,
            Sha256::digest(assistant_text.as_bytes()),
        ),
    ] {
        let row = turns
            .iter()
            .copied()
            .find(|row| {
                if let EventBody::SessionTurn { vendor_ref, .. } = &row.body {
                    vendor_ref.as_str() == vendor
                } else {
                    false
                }
            })
            .unwrap_or_else(|| panic!("the store has no captured turn for {vendor}"));
        let EventBody::SessionTurn {
            vendor_ref,
            role: stored_role,
            text: stored_text,
            evidence,
            ..
        } = &row.body
        else {
            panic!("the found row is not a session turn");
        };
        assert_eq!(
            vendor_ref.as_str(),
            vendor,
            "the vendor ref survives in the store"
        );
        match (stored_role, stored_text) {
            (se_store::Role::User, StoredText::Present(body)) if role == "user" => {
                assert_eq!(body, text);
            }
            (se_store::Role::Assistant, StoredText::Present(body)) if role == "assistant" => {
                assert_eq!(body, text);
            }
            other => panic!(
                "row {}: role/text mismatch: {:?}/{}",
                row.header.event.as_str(),
                other.0,
                stored_text_kind(other.1)
            ),
        }
        assert!(
            evidence.path.is_none(),
            "native capture must not invent a transcript path: {evidence:?}"
        );
        assert_eq!(
            evidence.sha256,
            Some(digest.into()),
            "the store records the SHA-256 of the exact text"
        );
        assert_eq!(
            evidence.length,
            text.len() as u64,
            "the evidence length is the text length"
        );
    }

    let context = judge.continuity(&host, &session, generation).required();
    assert_eq!(
        context.identity, issued.identity,
        "continuity returns the bound identity"
    );
    assert!(
        context.model_input.text.contains(user_text)
            && context.model_input.text.contains(assistant_text),
        "continuity carries both captured turns: {}",
        context.model_input.text
    );
    assert_eq!(
        context.continuity_summary.rows, 2,
        "the continuity summary counts both turns"
    );
    match context.packet {
        api::Read::Absent { checked } => {
            assert!(
                checked.contains("No boot packet"),
                "the packet refusal must name the reason: {checked}"
            );
        }
        other => panic!("the linked W3 binding issues no packet, got {other:?}"),
    }

    assert_public_turn(
        &judge,
        &user_event.id.0,
        "conv-capture-1",
        "user",
        "vt-1",
        user_text,
    )
    .required();
    assert_public_turn(
        &judge,
        &assistant_event.id.0,
        "conv-capture-1",
        "assistant",
        "vt-2",
        assistant_text,
    )
    .required();

    let receipt = judge.drain_close(&host, generation).required();
    assert!(receipt.writer_flushed, "the drain must flush: {receipt:?}");
}
#[path = "support/w3_native_task.rs"]
mod native_task;
