//! Independent continuity consumers over real captured turns and finite snapshots.
#![cfg(any(target_os = "linux", windows))]
use se_store::*;
use std::sync::Arc;
#[path = "support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "support/capture_fixture.rs"]
mod capture;

struct Turns {
    f: Fixture,
    direct: SqliteDirect,
    lease: Arc<Lease>,
    positions: Vec<StorePosition>,
    session: se_types::SessionId,
    source: RecordId,
}
impl Turns {
    fn new(count: u64) -> Result<Self, Box<dyn std::error::Error>> {
        let f = Fixture::new()?;
        let (mut direct, lease) = f.direct()?;
        let session = capture::session()?;
        let source = capture::record()?;
        capture::active(&f, &mut direct, &lease, &session, source)?;
        std::fs::write(f.home.join("transcript.jsonl"), b"ten bytes!".repeat(64))?;
        let mut h = Self {
            f,
            direct,
            lease,
            positions: Vec::new(),
            session,
            source,
        };
        for ordinal in 0..count {
            h.append(ordinal)?;
        }
        Ok(h)
    }
    fn append(&mut self, ordinal: u64) -> Check {
        let receipt = self.direct.append(
            capture::capture(
                &self.f,
                &self.session,
                self.source,
                b"first",
                ordinal * 10,
                ordinal + 1,
                &format!("turn-{ordinal:02}"),
            )?,
            &*self.lease,
        )?;
        self.positions.push(receipt.first);
        Ok(())
    }
    fn read(&self) -> Result<SqliteSnapshot, Box<dyn std::error::Error>> {
        Ok(self.direct.snapshot(self.f.self_scope(&self.f.a))?)
    }
    fn finish(self) -> Check {
        self.direct.close()?;
        drop(self.lease);
        Ok(())
    }
}
fn vendors(page: &se_types::Page<StoredEvent>) -> Vec<String> {
    page.items()
        .iter()
        .map(|event| match &event.body {
            EventBody::SessionTurn { vendor_ref, .. } => vendor_ref.clone(),
            _ => "UNEXPECTED NON-TURN".into(),
        })
        .collect()
}

/// Protects: item and byte budgets keep a chronological newest tail, count
/// omitted older work exactly, and never claim that a cut tail is complete.
#[test]
fn recent_turn_tail_honors_both_budgets_and_exact_omissions() -> Check {
    let h = Turns::new(7)?;
    let mut read = h.read()?;
    let tail = read.recent_turns(h.f.a.clone(), None, budget(3, 65536, None)?)?;
    assert_eq!(
        vendors(&tail),
        ["turn-04", "turn-05", "turn-06"],
        "newest chronological tail changed"
    );
    let fields = tail.window().fields().ok_or("window")?;
    assert!(
        matches!(fields.omitted_before,se_types::Omission::Known { count,reason:se_types::OmissionReason::Limit } if count.get()==4)
    );
    assert!(matches!(fields.omitted_after, se_types::Omission::None));
    assert_eq!(fields.stop_reason, se_types::StopReason::ItemLimit);
    assert!(!tail.window().complete());
    assert!(tail.next().is_none());
    let one = read.recent_turns(h.f.a.clone(), None, budget(1, 65536, None)?)?;
    let bytes = u32::try_from(one.window().fields().ok_or("single window")?.bytes)? + 1;
    let by_bytes = read.recent_turns(h.f.a.clone(), None, budget(7, bytes, None)?)?;
    assert_eq!(vendors(&by_bytes), ["turn-06"]);
    let fields = by_bytes.window().fields().ok_or("byte window")?;
    assert!(
        matches!(fields.omitted_before,se_types::Omission::Known { count,reason:se_types::OmissionReason::Budget } if count.get()==6)
    );
    assert_eq!(fields.stop_reason, se_types::StopReason::ByteLimit);
    assert!(!by_bytes.window().complete());
    assert_eq!(fields.unreadable, 0);
    assert_eq!(
        read.recent_turns(h.f.a.clone(), None, budget(7, 1, None)?)
            .err()
            .map(|e| e.code),
        Some(StoreErrorCode::ReadBudgetTooSmall)
    );
    drop(read);
    h.finish()
}

/// Protects: a since position is exclusive and frozen snapshots do not include
/// later turns; future/foreign positions and opaque page continuations refuse.
#[test]
fn recent_turn_since_and_snapshot_boundaries_are_not_page_continuations() -> Check {
    let mut h = Turns::new(4)?;
    let mut frozen = h.read()?;
    h.append(4)?;
    let old = frozen.recent_turns(
        h.f.a.clone(),
        Some(h.positions[1].clone()),
        budget(20, 65536, None)?,
    )?;
    assert_eq!(vendors(&old), ["turn-02", "turn-03"]);
    assert!(old.window().complete());
    assert_eq!(
        frozen
            .recent_turns(
                h.f.a.clone(),
                Some(h.positions[4].clone()),
                budget(20, 65536, None)?
            )
            .err()
            .map(|e| e.code),
        Some(StoreErrorCode::CursorStale)
    );
    let other = Turns::new(1)?;
    assert_eq!(
        frozen
            .recent_turns(
                h.f.a.clone(),
                Some(other.positions[0].clone()),
                budget(20, 65536, None)?
            )
            .err()
            .map(|e| e.code),
        Some(StoreErrorCode::CursorStale)
    );
    other.finish()?;
    let next = old
        .window()
        .fields()
        .ok_or("window")?
        .end_cursor
        .clone()
        .ok_or("end cursor")?;
    assert_eq!(
        frozen
            .recent_turns(h.f.a.clone(), None, budget(20, 65536, Some(next))?)
            .err()
            .map(|e| e.code),
        Some(StoreErrorCode::CursorInvalid)
    );
    drop(frozen);
    let mut fresh = h.read()?;
    let tail = fresh.recent_turns(
        h.f.a.clone(),
        Some(h.positions[3].clone()),
        budget(20, 65536, None)?,
    )?;
    assert_eq!(vendors(&tail), ["turn-04"]);
    assert!(tail.window().complete());
    let head = fresh.info().head.clone();
    let empty = fresh.recent_turns(h.f.a.clone(), head, budget(20, 65536, None)?)?;
    assert!(empty.items().is_empty());
    assert!(empty.window().complete());
    drop(fresh);
    h.finish()
}

/// Protects: another agent's turns remain private even though the tail index
/// and the same-project registry know those turns exist.
#[test]
fn recent_turns_preserve_the_bound_principal() -> Check {
    let h = Turns::new(2)?;
    let mut other = h.direct.snapshot(h.f.self_scope(&h.f.b))?;
    assert!(
        other
            .recent_turns(h.f.a.clone(), None, budget(10, 65536, None)?)
            .is_err(),
        "B read A's private turns"
    );
    let own = other.recent_turns(h.f.b.clone(), None, budget(10, 65536, None)?)?;
    assert!(own.items().is_empty());
    assert!(own.window().complete());
    drop(other);
    h.finish()
}

/// Protects: owner-preview positions cannot change their principal, target,
/// purpose or store when replayed as a continuity resume position.
#[test]
fn continuity_positions_bind_target_principal_purpose_and_store() -> Check {
    let h = Turns::new(1)?;
    let other = Turns::new(1)?;
    let owner = h.direct.snapshot(h.f.scoped(Visibility::Owner))?;
    let purpose = PositionPurpose::Continuity(h.f.a.clone());
    let cursor = owner.position_cursor(&h.positions[0], purpose.clone())?;
    assert_eq!(
        owner.cursor_position(&cursor, purpose.clone())?,
        h.positions[0]
    );
    for wrong in [
        PositionPurpose::Continuity(h.f.b.clone()),
        PositionPurpose::History,
        PositionPurpose::Checked,
        PositionPurpose::Receipt,
    ] {
        assert!(
            owner.cursor_position(&cursor, wrong).is_err(),
            "continuity cursor changed target or purpose"
        );
    }
    assert!(
        h.read()?.cursor_position(&cursor, purpose.clone()).is_err(),
        "owner cursor changed principal"
    );
    assert!(
        other
            .direct
            .snapshot(other.f.scoped(Visibility::Owner))?
            .cursor_position(&cursor, purpose)
            .is_err(),
        "continuity cursor changed store"
    );
    drop(owner);
    other.finish()?;
    h.finish()
}

#[path = "support/wave2_continuity_fixture.rs"]
mod governing_fixture;
use governing_fixture::*;

/// Protects: B receives current ratified project law and its exact proposal
/// under SelfOnly, while A's pending/withdrawn/superseded requests stay private.
#[test]
fn bound_agent_sees_current_project_law_without_private_requests() -> Check {
    let h = Governing::new()?;
    let mut reader = h.reader()?;
    assert_eq!(
        reader.decision_count(false)?,
        3,
        "SelfOnly count disclosed decisions outside governing law"
    );
    assert_eq!(
        reader.decision_count(true)?,
        0,
        "B's count disclosed A's pending ruling request"
    );
    let laws = reader.governing_decisions(budget(20, 65536, None)?)?;
    let mut text = laws
        .items()
        .iter()
        .map(proposal)
        .collect::<Result<Vec<_>, _>>()?;
    text.sort();
    assert_eq!(
        text,
        ["visible first", "visible replacement", "visible second"]
    );
    assert!(laws.window().complete());
    assert!(
        reader.working_state(h.f.a.clone()).is_err(),
        "governing read widened B's snapshot to private state"
    );
    drop(reader);
    h.finish()
}

/// Protects: a cut governing page names an exact omitted-after count; reading
/// the remaining pages uses that same frozen project law without losing heads.
#[test]
fn governing_page_budget_counts_omitted_law_exactly() -> Check {
    let h = Governing::new()?;
    let mut reader = h.reader()?;
    let first = reader.governing_decisions(budget(1, 65536, None)?)?;
    assert_eq!(first.items().len(), 1);
    assert!(
        matches!(first.window().fields().ok_or("window")?.omitted_after,
        se_types::Omission::Known { count,.. } if count.get()==2),
        "governing truncation did not count two omitted rulings"
    );
    assert!(!first.window().complete());
    let next = first
        .next()
        .cloned()
        .ok_or("governing continuation absent")?;
    let remaining = reader.governing_decisions(budget(10, 65536, Some(next))?)?;
    assert_eq!(remaining.items().len(), 2);
    assert!(remaining.window().complete());
    assert_eq!(reader.decision_count(false)?, 3);
    for record in first.items().iter().chain(remaining.items()) {
        assert!(!proposal(record)?.contains("SECRET"));
    }
    drop(reader);
    h.finish()
}

/// Current project law must carry the exact ratified proposal even for an owner.
#[test]
fn governing_owner_read_retains_exact_proposal_text() -> Check {
    let h = Governing::new()?;
    let mut owner = h.owner_reader()?;
    let laws = owner.governing_decisions(budget(20, 65536, None)?)?;
    assert_eq!(laws.items().len(), 3);
    for law in laws.items() {
        proposal(law)?;
    }
    drop(owner);
    h.finish()
}
/// A bound B must not count A's private pending request.
#[test]
fn pending_count_does_not_disclose_another_agents_request() -> Check {
    let h = Governing::new()?;
    let mut reader = h.reader()?;
    assert_eq!(
        reader.decision_count(true)?,
        0,
        "private pending request disclosed"
    );
    drop(reader);
    h.finish()
}

/// Default decision pages contain current governing and pending heads only.
#[test]
fn default_decision_query_excludes_rejected_retracted_and_superseded_heads() -> Check {
    let h = Governing::new()?;
    let mut owner = h.owner_reader()?;
    let page = owner.decisions(
        DecisionQuery {
            id: None,
            pending_only: false,
            history: false,
        },
        budget(20, 65536, None)?,
    )?;
    assert_eq!(
        page.items().len(),
        4,
        "default decision query included terminal history"
    );
    assert!(page.window().complete());
    drop(owner);
    h.finish()
}
/// History=true adds terminal decision heads without turning into an event stream.
#[test]
fn historical_decision_query_retains_terminal_heads() -> Check {
    let h = Governing::new()?;
    let mut owner = h.owner_reader()?;
    let page = owner.decisions(
        DecisionQuery {
            id: None,
            pending_only: false,
            history: true,
        },
        budget(20, 65536, None)?,
    )?;
    assert_eq!(
        page.items().len(),
        7,
        "decision history lost retained heads"
    );
    assert!(page.window().complete());
    drop(owner);
    h.finish()
}
/// Pending and exact-ID selectors remain independent of the history inclusion flag.
#[test]
fn pending_decision_query_and_exact_id_do_not_widen_to_other_heads() -> Check {
    let h = Governing::new()?;
    let mut owner = h.owner_reader()?;
    let pending = owner.decisions(
        DecisionQuery {
            id: None,
            pending_only: true,
            history: false,
        },
        budget(20, 65536, None)?,
    )?;
    assert_eq!(pending.items().len(), 1);
    let EventBody::DecisionProposed { decision, .. } = &pending.items()[0].current.body else {
        return Err("pending query returned a non-proposal".into());
    };
    let exact = owner.decisions(
        DecisionQuery {
            id: Some(decision.clone()),
            pending_only: false,
            history: false,
        },
        budget(20, 65536, None)?,
    )?;
    assert_eq!(exact.items().len(), 1);
    assert_eq!(
        exact.items()[0].current.header.event,
        pending.items()[0].current.header.event
    );
    drop(owner);
    h.finish()
}

/// SelfOnly is allowed to read current governing law, without inheriting an
/// owner's visibility of another agent's pending or terminal decision heads.
#[test]
fn self_only_decision_query_exposes_only_current_governing_law() -> Check {
    let h = Governing::new()?;
    let mut reader = h.reader()?;
    let page = reader.decisions(
        DecisionQuery {
            id: None,
            pending_only: false,
            history: false,
        },
        budget(20, 65536, None)?,
    )?;
    assert_eq!(
        page.items().len(),
        3,
        "SelfOnly decision page widened to private or terminal heads"
    );
    assert!(page.window().complete());
    for head in page.items() {
        proposal(head)?;
    }
    let pending = reader.decisions(
        DecisionQuery {
            id: None,
            pending_only: true,
            history: false,
        },
        budget(20, 65536, None)?,
    )?;
    assert!(
        pending.items().is_empty(),
        "SelfOnly query disclosed another agent's pending request"
    );
    assert!(pending.window().complete());
    drop(reader);
    h.finish()
}

/// Retired law stays public through its dedicated detail path; never-ratified
/// foreign proposals and the generic immutable event reader remain private.
#[test]
fn retired_law_history_and_detail_do_not_grant_generic_event_authority() -> Check {
    let mut h = Governing::new()?;
    let retired = h.retired_ratified()?;
    let mut read = h.reader()?;
    let history = read.decisions(
        DecisionQuery {
            id: None,
            pending_only: false,
            history: true,
        },
        budget(100, 65536, None)?,
    )?;
    let texts = history
        .items()
        .iter()
        .map(proposal)
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    assert_eq!(texts.len(), 5);
    assert!(texts.iter().any(|text| text == "SECRET OLD PROPOSAL"));
    assert!(texts.iter().any(|text| text == "retired project law"));
    for secret in ["SECRET A PENDING", "SECRET REJECTED", "SECRET RETRACTED"] {
        assert!(!texts.iter().any(|text| text.contains(secret)));
    }
    let detail =
        present(read.decision_detail_transitions(retired.clone(), budget(1, 65536, None)?)?)?;
    let cursor = detail
        .next()
        .cloned()
        .ok_or("detail continuation missing")?;
    let rest = present(read.decision_detail_transitions(
        retired.clone(),
        budget(100, 65536, Some(cursor.clone()))?,
    )?)?;
    assert_eq!(detail.items().len() + rest.items().len(), 3);
    assert_eq!(
        read.decision_transitions(retired.clone(), budget(100, 65536, Some(cursor))?)
            .err()
            .map(|e| e.code),
        Some(StoreErrorCode::CursorInvalid)
    );
    assert_eq!(
        read.decision_transitions(retired, budget(100, 65536, None)?)
            .err()
            .map(|e| e.code),
        Some(StoreErrorCode::ScopeMismatch)
    );
    assert!(read.working_state(h.f.a.clone()).is_err());
    drop(read);
    h.finish()
}

/// Narrowing retains the original WAL pin and cannot move a project-bound or
/// agent reader to a different tenant/project.
#[test]
fn owner_registry_selection_narrows_once_without_reopening_its_snapshot() -> Check {
    let f = Fixture::new()?;
    let (mut direct, lease) = f.direct()?;
    let scope = ReadScope {
        admission: f.admission(Scope::Registry, Actor::Human(f.owner.clone())),
        visibility: Visibility::Owner,
    };
    let mut frozen = direct.snapshot(scope)?;
    let n = serial();
    let project = se_types::ProjectId::from_parts(1_700_000_000_000 + n, [n as u8; 10])?;
    direct.append(
        f.batch(
            f.admission(
                Scope::Project(project.clone()),
                Actor::Human(f.owner.clone()),
            ),
            None,
            vec![EventBody::ProjectRegistered {
                project: project.clone(),
                name: "Later project".into(),
                roots: vec![],
                owner: f.owner.clone(),
                history_from: None,
                expected: Expected::Absent,
            }],
        )?,
        &*lease,
    )?;
    frozen.select_project(project.clone())?;
    assert!(
        matches!(
            frozen.project(project.clone())?,
            se_types::Read::Absent { .. }
        ),
        "narrowing reopened the snapshot and saw later registration"
    );
    assert_eq!(
        frozen
            .select_project(f.project.clone())
            .err()
            .map(|e| e.code),
        Some(StoreErrorCode::ScopeMismatch)
    );
    frozen.select_project(project.clone())?; // exact same selection changes nothing
    drop(frozen);
    let mut owner = direct.snapshot(f.scoped(Visibility::Owner))?;
    assert_eq!(
        owner.select_project(project.clone()).err().map(|e| e.code),
        Some(StoreErrorCode::ScopeMismatch)
    );
    drop(owner);
    let mut agent = direct.snapshot(f.self_scope(&f.a))?;
    assert_eq!(
        agent.select_project(project).err().map(|e| e.code),
        Some(StoreErrorCode::ScopeMismatch)
    );
    drop(agent);
    direct.close()?;
    drop(lease);
    Ok(())
}
