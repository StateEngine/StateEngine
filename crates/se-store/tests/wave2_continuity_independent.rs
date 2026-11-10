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
            Some(request(&format!(
                "fixture-wave2_continuity_independent-527-{}",
                serial()
            ))?),
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
