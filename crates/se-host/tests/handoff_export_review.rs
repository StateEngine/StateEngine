//! Reviewer checks for `handoff.export` over the real store and captured turns:
//! owner and self authority, cross-agent refusal, honest byte budgets and
//! cursor continuation. An export never writes.
#![cfg(any(target_os = "linux", windows))]
use se_core::{
    commit::Cx,
    ops::continuity::handoff::{HandoffExport, HandoffOutput, export},
};
use se_store::*;
use se_types::{AgentId, Cursor, Detail, SessionId};
#[path = "../../se-store/tests/support/store_fixture.rs"]
mod fixture;
use fixture::*;
#[path = "../../se-store/tests/support/capture_fixture.rs"]
mod capture;
use std::sync::Arc;

const PRIVATE: &str = "private A handoff state 🦊é ";

struct Harness {
    f: Fixture,
    direct: SqliteDirect,
    lease: Arc<Lease>,
    a: SessionId,
    b: SessionId,
    source: RecordId,
}

impl Harness {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let f = Fixture::new()?;
        let (mut direct, lease) = f.direct()?;
        let a = capture::session()?;
        let b = capture::session()?;
        let source = capture::record()?;
        capture::active(&f, &mut direct, &lease, &a, source)?;
        std::fs::write(f.home.join("transcript.jsonl"), b"ten bytes!".repeat(8))?;
        for ordinal in 0..6 {
            direct.append(
                capture::capture(
                    &f,
                    &a,
                    source,
                    b"first",
                    ordinal * 10,
                    ordinal + 1,
                    &format!("handoff-turn-{ordinal}"),
                )?,
                &*lease,
            )?;
        }
        direct.append(
            f.batch(
                f.owner_project(),
                Some(fixture::request(&format!(
                    "fixture-handoff_export_review-b-{}",
                    serial()
                ))?),
                vec![capture::prepared(&f, &b, &f.b), capture::activated(&b)?],
            )?,
            &*lease,
        )?;
        direct.append(
            f.working(&PRIVATE.repeat(300), Expected::Absent, "handoff-state")?,
            &*lease,
        )?;
        Ok(Self {
            f,
            direct,
            lease,
            a,
            b,
            source,
        })
    }

    fn agent_scope(&self, agent: &AgentId, session: &SessionId) -> ReadScope {
        let mut scope = self.f.self_scope(agent);
        scope.admission.session = Some(session.clone());
        scope
    }

    fn export(
        &self,
        scope: ReadScope,
        input: HandoffExport,
    ) -> Result<se_types::Result<HandoffOutput>, Box<dyn std::error::Error>> {
        let admission = scope.admission.clone();
        let mut read = self.direct.snapshot(scope)?;
        Ok(export(
            input,
            &mut Cx {
                read: &mut read,
                admission: &admission,
            },
        ))
    }

    fn owner(
        &self,
        input: HandoffExport,
    ) -> Result<se_types::Result<HandoffOutput>, Box<dyn std::error::Error>> {
        self.export(self.f.scoped(Visibility::Owner), input)
    }

    fn head(&self) -> Result<Option<StorePosition>, Box<dyn std::error::Error>> {
        Ok(self
            .direct
            .snapshot(self.f.scoped(Visibility::Owner))?
            .info()
            .head)
    }

    fn finish(self) -> Check {
        self.direct.close()?;
        drop(self.lease);
        Ok(())
    }
}

fn request(from: Option<&AgentId>, budget: u32, since: Option<Cursor>) -> HandoffExport {
    HandoffExport {
        from: from.map(|agent| agent.as_str().to_owned()),
        budget,
        since,
    }
}

fn honest_bytes(output: &HandoffOutput, budget: u32) {
    assert_eq!(
        output.bytes,
        output.text.len() as u64,
        "byte count is not the text length"
    );
    assert!(
        output.bytes <= u64::from(budget),
        "{} bytes exceed the {budget} budget",
        output.bytes
    );
}

/// Protects: the owner exports any project agent's committed turns and working
/// state, the export names that agent and session, and nothing is written.
#[test]
fn owner_exports_any_project_agent_without_writing() -> Check {
    let h = Harness::new()?;
    let before = h.head()?;
    let out = h.owner(request(Some(&h.f.a), 16384, None))??;
    assert_eq!(out.agent.id, h.f.a);
    assert_eq!(out.session.as_ref(), Some(&h.a));
    honest_bytes(&out, 16384);
    assert!(out.complete, "an export that fits was marked incomplete");
    assert!(
        !out.text.contains("[truncated"),
        "a complete export carries a truncation marker"
    );
    for ordinal in 0..6 {
        assert!(
            out.text
                .contains(&format!("captured handoff-turn-{ordinal}")),
            "committed turn {ordinal} is missing"
        );
    }
    assert!(
        out.text.contains(PRIVATE.trim_end()),
        "working state is missing"
    );

    let other = h.owner(request(Some(&h.f.b), 16384, None))??;
    assert_eq!(other.agent.id, h.f.b);
    assert_eq!(other.session.as_ref(), Some(&h.b));
    assert!(
        !other.text.contains(PRIVATE.trim_end()),
        "agent A's state leaked into B's export"
    );
    assert!(
        !other.text.contains("handoff-turn-"),
        "agent A's turns leaked into B's export"
    );
    assert_eq!(h.head()?, before, "an export wrote to the store");
    h.finish()
}

/// Protects: the owner must name an agent, and the refusal offers a command.
#[test]
fn owner_without_an_agent_is_told_how_to_choose_one() -> Check {
    let h = Harness::new()?;
    let Err(error) = h.owner(request(None, 8192, None))? else {
        return Err("an owner export without --from succeeded".into());
    };
    assert!(
        matches!(error.body.detail(), Detail::UsageMissingArgument(_)),
        "unexpected refusal: {error}"
    );
    assert!(
        error.body.recovery_command().is_some(),
        "the refusal names no command to choose an agent: {error}"
    );
    h.finish()
}

/// Protects: a bound agent exports itself by default or by its own selector,
/// with its bound session, and both spellings give the same packet.
#[test]
fn bound_agent_exports_itself() -> Check {
    let h = Harness::new()?;
    let implicit = h.export(h.agent_scope(&h.f.a, &h.a), request(None, 16384, None))??;
    let explicit = h.export(
        h.agent_scope(&h.f.a, &h.a),
        request(Some(&h.f.a), 16384, None),
    )??;
    assert_eq!(implicit.agent.id, h.f.a);
    assert_eq!(implicit.session.as_ref(), Some(&h.a));
    assert_eq!(
        implicit.text, explicit.text,
        "self selector changed the packet"
    );
    assert!(implicit.text.contains("captured handoff-turn-5"));
    honest_bytes(&implicit, 16384);
    h.finish()
}

/// Protects: an agent can never export another agent's history.
#[test]
fn agent_cannot_export_another_agent() -> Check {
    let h = Harness::new()?;
    let Err(error) = h.export(
        h.agent_scope(&h.f.b, &h.b),
        request(Some(&h.f.a), 16384, None),
    )?
    else {
        return Err("agent B exported agent A's history".into());
    };
    assert!(
        matches!(error.body.detail(), Detail::OwnerRequired(_)),
        "unexpected refusal: {error}"
    );
    assert!(
        !error.to_string().contains(PRIVATE.trim_end()),
        "the refusal leaked A's state"
    );
    h.finish()
}

/// Protects: a tight budget keeps the newest turn, drops the oldest, stays
/// within the byte budget, says it is incomplete, and is deterministic.
#[test]
fn tight_budget_trims_oldest_first_and_reports_incomplete() -> Check {
    let h = Harness::new()?;
    let first = h.owner(request(Some(&h.f.a), 1024, None))??;
    let again = h.owner(request(Some(&h.f.a), 1024, None))??;
    honest_bytes(&first, 1024);
    assert!(!first.complete, "a trimmed export claimed to be complete");
    assert!(
        first.text.contains("[truncated"),
        "a trimmed export has no truncation marker"
    );
    assert!(
        first.text.contains("captured handoff-turn-5"),
        "the newest turn was dropped"
    );
    assert!(
        !first.text.contains("captured handoff-turn-0"),
        "the oldest turn outlived the trim"
    );
    assert_eq!(
        first.text, again.text,
        "the same store state gave two packets"
    );
    assert_eq!(first.cursor, again.cursor);
    h.finish()
}

/// Protects: out-of-range budgets are refused before any read.
#[test]
fn out_of_range_budgets_are_refused() -> Check {
    let h = Harness::new()?;
    for budget in [0u32, 255, 16385] {
        let Err(error) = h.owner(request(Some(&h.f.a), budget, None))? else {
            return Err(format!("budget {budget} was accepted").into());
        };
        assert!(
            matches!(error.body.detail(), Detail::UsageInvalidValue(_)),
            "budget {budget}: unexpected refusal {error}"
        );
    }
    h.finish()
}

/// Protects: a cursor continues after the last export; only newer turns
/// return, and a caught-up export carries no turns.
#[test]
fn cursor_continues_with_only_newer_turns() -> Check {
    let mut h = Harness::new()?;
    let first = h.owner(request(Some(&h.f.a), 16384, None))??;
    h.direct.append(
        capture::capture(&h.f, &h.a, h.source, b"first", 60, 7, "handoff-turn-6")?,
        &*h.lease,
    )?;
    let next = h.owner(request(Some(&h.f.a), 16384, Some(first.cursor.clone())))??;
    assert!(
        next.text.contains("captured handoff-turn-6"),
        "the new turn is missing"
    );
    assert!(
        !next.text.contains("captured handoff-turn-5"),
        "an exported turn repeated"
    );
    assert_ne!(next.cursor, first.cursor, "the cursor did not advance");
    honest_bytes(&next, 16384);

    let caught_up = h.owner(request(Some(&h.f.a), 16384, Some(next.cursor.clone())))??;
    assert!(
        !caught_up.text.contains("handoff-turn-"),
        "a caught-up export repeated turns"
    );
    h.finish()
}

/// Protects: a well-formed cursor that this store never issued is refused,
/// never read as "nothing new".
#[test]
fn foreign_cursor_is_refused() -> Check {
    let h = Harness::new()?;
    let foreign = se_core::ops::continuity::resume_since("not-a-cursor".into())?;
    let Err(error) = h.owner(request(Some(&h.f.a), 16384, Some(foreign)))? else {
        return Err("a foreign cursor exported as caught up".into());
    };
    assert!(
        matches!(error.body.detail(), Detail::CursorInvalid(_)),
        "unexpected refusal: {error}"
    );
    h.finish()
}
