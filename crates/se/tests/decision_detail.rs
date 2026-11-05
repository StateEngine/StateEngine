#![allow(
    dead_code,
    reason = "The shared real native fixture supports several public API consumers."
)]
use se_store::*;
use se_types::{DecisionId, EventId, ProjectId};
use std::{
    process::{Command, Output},
    sync::Arc,
};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;

type Outcome<T> = Result<T, Box<dyn std::error::Error>>;
fn decision() -> Outcome<DecisionId> {
    Ok(DecisionId::from_parts(
        1_700_000_000_000 + serial(),
        [93; 10],
    )?)
}
fn setup() -> Outcome<(Fixture, SqliteDirect, Arc<Lease>)> {
    let f = Fixture::new()?;
    let (mut store, lease) = f.direct()?;
    store.append(
        f.batch(
            f.owner_project(),
            Some(fixture::request(&format!(
                "fixture-decision_detail-26-{}",
                serial()
            ))?),
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
    Ok((f, store, lease))
}
fn propose(
    f: &Fixture,
    store: &mut SqliteDirect,
    lease: &Lease,
    id: &DecisionId,
    statement: &str,
    prior: Option<DecisionId>,
) -> Outcome<EventId> {
    Ok(store
        .append(
            f.batch(
                f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone())),
                Some(fixture::request(&format!(
                    "fixture-decision_detail-53-{}",
                    serial()
                ))?),
                vec![EventBody::DecisionProposed {
                    decision: id.clone(),
                    key: "policy.files".into(),
                    statement: InputText::Inline(statement.into()),
                    rationale: Some(InputText::Inline("preserve the user's work".into())),
                    prior,
                    kind: DecisionKind::Decision,
                }],
            )?,
            lease,
        )?
        .primary_event)
}
fn append(
    f: &Fixture,
    store: &mut SqliteDirect,
    lease: &Lease,
    body: EventBody<InputText>,
) -> Outcome<EventId> {
    Ok(store
        .append(
            f.batch(
                f.owner_project(),
                Some(fixture::request(&format!(
                    "fixture-decision_detail-76-{}",
                    serial()
                ))?),
                vec![body],
            )?,
            lease,
        )?
        .primary_event)
}
fn read(f: &Fixture, id: &DecisionId, json: bool) -> Outcome<(Output, serde_json::Value)> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_se"));
    if json {
        command.arg("--json");
    }
    command.arg("--home").arg(&f.options.state_directory).args([
        "--project",
        f.project.as_str(),
        "decision",
        "show",
        id.as_str(),
    ]);
    for name in [
        "SE_HOME",
        "SE_PROJECT",
        "SE_CONFIG",
        "SE_LOG",
        "SE_SESSION",
        "CLAUDECODE",
        "CODEX_THREAD_ID",
        "CODEX_CI",
    ] {
        command.env_remove(name);
    }
    let output = command.output()?;
    let value = if json {
        serde_json::from_slice(&output.stdout).map_err(|error| {
            format!(
                "decision detail JSON: {error}; stdout={}; stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        })?
    } else {
        serde_json::Value::Null
    };
    Ok((output, value))
}
fn detail<'a>(output: &Output, value: &'a serde_json::Value) -> Outcome<&'a serde_json::Value> {
    assert!(
        output.status.success(),
        "decision show refused: {value}; {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(value["schema"], "se.decision/v1");
    assert_eq!(value["decision"]["state"], "present");
    Ok(&value["decision"]["value"])
}
fn transitions(
    value: &serde_json::Value,
    expected: &[(&str, &EventId)],
    owner: &str,
    agent: &str,
) -> Check {
    let rows = value["transitions"]
        .as_array()
        .ok_or("missing decision transitions")?;
    assert_eq!(
        rows.len(),
        expected.len(),
        "unrelated, duplicate or missing transition"
    );
    for (row, (action, event)) in rows.iter().zip(expected) {
        assert_eq!(row["action"], *action);
        assert_eq!(row["event_id"], event.as_str());
        assert_eq!(
            row["by"]["id"],
            if *action == "propose" { agent } else { owner }
        );
        assert!(row["at"].as_str().is_some_and(|v| !v.is_empty()));
    }
    Ok(())
}

/// Protects: public decision detail returns the full original statement and immutable ordered transitions, including the incoming supersede event, without treating that link as another revision of the replacement.
#[test]
fn supersede_detail_keeps_both_decision_histories() -> Check {
    let (f, mut store, lease) = setup()?;
    let prior = decision()?;
    let replacement = decision()?;
    let statement = "retain every user's file 🦀\n".repeat(100);
    let p = propose(&f, &mut store, &lease, &prior, &statement, None)?;
    let a = append(
        &f,
        &mut store,
        &lease,
        EventBody::DecisionRatified {
            decision: prior.clone(),
            expected: revision(1)?,
            approval: p.clone(),
        },
    )?;
    let rp = propose(
        &f,
        &mut store,
        &lease,
        &replacement,
        "new governing statement",
        Some(prior.clone()),
    )?;
    let ra = append(
        &f,
        &mut store,
        &lease,
        EventBody::DecisionRatified {
            decision: replacement.clone(),
            expected: revision(1)?,
            approval: rp.clone(),
        },
    )?;
    let Expected::Revision(two) = revision(2)? else {
        return Err("revision helper".into());
    };
    let s = append(
        &f,
        &mut store,
        &lease,
        EventBody::DecisionSuperseded {
            prior: prior.clone(),
            replacement: replacement.clone(),
            prior_expected: two,
            replacement_expected: two,
            approval: ra.clone(),
        },
    )?;
    // A later unrelated event must not enter either exact decision's detail.
    store.append(
        f.working("unrelated", Expected::Absent, "detail-unrelated")?,
        &*lease,
    )?;
    let head = store.info()?.head;
    let (output, value) = read(&f, &prior, true)?;
    let old = detail(&output, &value)?;
    assert_eq!(old["statement"]["text"], statement);
    assert_eq!(old["statement"]["complete"], true);
    assert_eq!(old["statement"]["bytes"], statement.len());
    assert_eq!(old["state"], "superseded");
    assert_eq!(old["revision"], 3);
    assert_eq!(old["governing"], false);
    assert_eq!(old["proposed_by"]["id"], f.a.as_str());
    assert_eq!(old["superseded_by"], replacement.as_str());
    transitions(
        old,
        &[("propose", &p), ("ratify", &a), ("supersede", &s)],
        f.owner.as_str(),
        f.a.as_str(),
    )?;
    let (output, value) = read(&f, &replacement, true)?;
    let new = detail(&output, &value)?;
    assert_eq!(new["state"], "ratified");
    assert_eq!(new["revision"], 2);
    assert_eq!(new["governing"], true);
    assert_eq!(new["supersedes"], prior.as_str());
    transitions(
        new,
        &[("propose", &rp), ("ratify", &ra), ("supersede", &s)],
        f.owner.as_str(),
        f.a.as_str(),
    )?;
    let (human, _) = read(&f, &prior, false)?;
    assert!(human.status.success());
    let text = String::from_utf8(human.stdout)?;
    assert!(
        text.contains("State: replaced; revision 3; applies to this project: no"),
        "{text}"
    );
    assert!(text.contains("Approved by Owner"), "{text}");
    let listed = Command::new(env!("CARGO_BIN_EXE_se"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").ok_or("PATH")?)
        .arg("--home")
        .arg(&f.options.state_directory)
        .args([
            "--project",
            f.project.as_str(),
            "decision",
            "list",
            "--history",
        ])
        .output()?;
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed = String::from_utf8(listed.stdout)?;
    assert!(
        listed.contains(prior.as_str()) && listed.contains(replacement.as_str()),
        "{listed}"
    );
    assert!(
        text.contains(&statement),
        "default detail truncated the statement"
    );
    assert_eq!(store.info()?.head, head);
    store.close()?;
    Ok(())
}

/// Protects: rejection and retraction remain distinct immutable detail transitions with their original public reasons.
#[test]
fn rejected_and_retracted_reasons_survive_detail() -> Check {
    let (f, mut store, lease) = setup()?;
    for rejected in [true, false] {
        let id = decision()?;
        let p = propose(&f, &mut store, &lease, &id, "review this proposal", None)?;
        let reason = if rejected {
            "owner rejects this rationale"
        } else {
            "owner withdraws this proposal"
        };
        let body = if rejected {
            EventBody::DecisionRejected {
                decision: id.clone(),
                expected: revision(1)?,
                reason: InputText::Inline(reason.into()),
            }
        } else {
            EventBody::DecisionRetracted {
                decision: id.clone(),
                expected: revision(1)?,
                reason: InputText::Inline(reason.into()),
            }
        };
        let last = append(&f, &mut store, &lease, body)?;
        let (output, value) = read(&f, &id, true)?;
        let row = detail(&output, &value)?;
        let action = if rejected { "reject" } else { "retract" };
        assert_eq!(
            row["state"],
            if rejected { "rejected" } else { "retracted" }
        );
        assert_eq!(row["reason"], reason);
        transitions(
            row,
            &[("propose", &p), (action, &last)],
            f.owner.as_str(),
            f.a.as_str(),
        )?;
        assert_eq!(row["transitions"][1]["reason"], reason);
    }
    store.close()?;
    Ok(())
}

/// Protects: public detail distinguishes unknown absence from a known foreign decision without exposing its statement or widening project lists.
#[test]
fn unknown_and_foreign_decision_ids_are_distinct() -> Check {
    let (f, mut store, lease) = setup()?;
    let (output, value) = read(&f, &decision()?, true)?;
    assert!(output.status.success(), "unknown decision refused: {value}");
    assert_eq!(value["schema"], "se.decision/v1");
    assert_eq!(value["decision"]["state"], "absent");
    let project = ProjectId::from_parts(1_700_000_000_000 + serial(), [94; 10])?;
    let id = decision()?;
    let admission = f.admission(
        Scope::Project(project.clone()),
        Actor::Human(f.owner.clone()),
    );
    store.append(
        f.batch(
            admission.clone(),
            Some(fixture::request(&format!(
                "fixture-decision_detail-311-{}",
                serial()
            ))?),
            vec![
                EventBody::ProjectRegistered {
                    project,
                    name: "Other".into(),
                    roots: vec![],
                    owner: f.owner.clone(),
                    history_from: None,
                    expected: Expected::Absent,
                },
                EventBody::DecisionProposed {
                    decision: id.clone(),
                    key: "private.policy".into(),
                    statement: InputText::Inline("foreign secret statement".into()),
                    rationale: None,
                    prior: None,
                    kind: DecisionKind::Decision,
                },
            ],
        )?,
        &*lease,
    )?;
    let head = store.info()?.head;
    let (output, value) = read(&f, &id, true)?;
    assert!(
        !output.status.success(),
        "foreign decision became absence: {value}"
    );
    assert_eq!(value["code"], "capability-invalid");
    assert!(!String::from_utf8(output.stdout)?.contains("foreign secret statement"));
    assert_eq!(store.info()?.head, head);
    store.close()?;
    Ok(())
}

/// Protects: a pending proposal is readable before any owner decision, with truthful null decision metadata and exactly its immutable proposal transition.
#[test]
fn pending_detail_has_no_fabricated_owner_transition() -> Check {
    let (f, mut store, lease) = setup()?;
    let id = decision()?;
    let proposed = propose(
        &f,
        &mut store,
        &lease,
        &id,
        "awaiting an owner decision",
        None,
    )?;
    let head = store.info()?.head;
    let (output, value) = read(&f, &id, true)?;
    let row = detail(&output, &value)?;
    assert_eq!(row["state"], "pending");
    assert_eq!(row["revision"], 1);
    assert_eq!(row["governing"], false);
    for key in ["decided_by", "decided_at", "reason", "superseded_by"] {
        assert!(
            row.get(key).is_some_and(serde_json::Value::is_null),
            "pending metadata {key}: {row}"
        );
    }
    transitions(
        row,
        &[("propose", &proposed)],
        f.owner.as_str(),
        f.a.as_str(),
    )?;
    assert_eq!(store.info()?.head, head);
    store.close()?;
    Ok(())
}

/// Protects: a requested decision whose retained statement bytes are damaged returns the declared unreadable detail with exit 3, never a fabricated statement, absence or successful empty history.
#[test]
fn damaged_decision_statement_is_unreadable_exit_three() -> Check {
    let (f, mut store, lease) = setup()?;
    let id = decision()?;
    let proposed = propose(
        &f,
        &mut store,
        &lease,
        &id,
        "original retained statement",
        None,
    )?;
    let native = proposed
        .canonical_bytes()?
        .ok_or("canonical fixture event")?;
    let database = rusqlite::Connection::open(f.options.state_directory.join("state.db"))?;
    // Deliberate corruption of this disposable fixture, bypassing only its
    // immutability trigger; production writes cannot take this path.
    database.execute_batch("DROP TRIGGER payloads_no_update")?;
    assert_eq!(database.execute("UPDATE payloads SET content=CAST('damaged statement' AS BLOB) WHERE event_seq=(SELECT seq FROM events WHERE event_id=?) AND field='statement'", [native.as_slice()])?, 1);
    let head = store.info()?.head;
    let (output, value) = read(&f, &id, true)?;
    assert_eq!(
        output.status.code(),
        Some(3),
        "wrong damaged-detail exit: {value}"
    );
    assert_eq!(value["schema"], "se.decision/v1");
    assert_eq!(value["decision"]["state"], "unreadable");
    assert!(value["decision"].get("value").is_none());
    assert_eq!(store.info()?.head, head);
    store.close()?;
    Ok(())
}
