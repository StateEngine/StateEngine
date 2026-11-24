//! Deterministic, model-agnostic cross-model context handoff export.
//! Reads strictly through the caller's admitted Snapshot from committed
//! `session.turn` events, working state, and active ratified decisions.
use super::{identity, packet, read};
use crate::{
    commit::Cx,
    ops::{
        inputs::{Validate, bounded},
        receipt,
    },
    scope,
    store_error::store_error,
};
use schemars::JsonSchema;
use se_store::{
    EventBody, HistoryDirection, HistoryFamily, HistoryQuery, Role, Snapshot, StoredText,
    TranscriptFilter,
};
use se_types::{AgentId, Cursor, DecisionId, Named, Read, Result, SeError, SessionId};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

pub const MIN_HANDOFF_BYTES: u32 = 256;
pub const DEFAULT_HANDOFF_BYTES: u32 = 8192;
pub const MAX_HANDOFF_BYTES: u32 = 16384;
const TURN_LIMIT: u32 = 100;
const DECISION_LIMIT: u32 = 100;

fn default_budget() -> u32 {
    DEFAULT_HANDOFF_BYTES
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HandoffExport {
    /// Optional agent selector (name or ID). Bound agents default to self;
    /// owners specify a project agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// Maximum UTF-8 bytes in the exported handoff text (256..16384, default 8192).
    #[serde(default = "default_budget")]
    pub budget: u32,
    /// Optional opaque continuity cursor for incremental export.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<Cursor>,
}

impl Validate for HandoffExport {
    fn validate(&self) -> Result<()> {
        if let Some(from) = &self.from {
            bounded("from", from, 512, false)?;
        }
        if !(MIN_HANDOFF_BYTES..=MAX_HANDOFF_BYTES).contains(&self.budget) {
            return Err(SeError::invalid("budget", "256..16384 UTF-8 bytes"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct HandoffOutput {
    pub agent: Named<AgentId>,
    pub session: Option<SessionId>,
    pub text: String,
    pub bytes: u64,
    pub cursor: Cursor,
    pub complete: bool,
}

struct HandoffTurn {
    at: String,
    role: &'static str,
    text: String,
    clipped: bool,
}

struct ActiveDecision {
    id: DecisionId,
    key: String,
    statement: String,
    rationale: Option<String>,
    active: bool,
}

enum WorkingNote {
    Absent,
    Present { text: String, clipped: bool },
    Unreadable,
}

struct PacketDraft {
    identity: identity::HandoffIdentity,
    working: WorkingNote,
    decisions: Vec<ActiveDecision>,
    turns: Vec<HandoffTurn>,
    source_incomplete: bool,
    truncated: bool,
    budget: u32,
}

impl PacketDraft {
    fn is_complete(&self) -> bool {
        !self.source_incomplete
            && !self.truncated
            && !matches!(
                self.working,
                WorkingNote::Unreadable | WorkingNote::Present { clipped: true, .. }
            )
            && !self.turns.iter().any(|turn| turn.clipped)
    }

    fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# Context Handoff");
        let _ = writeln!(
            out,
            "Agent: {} ({})",
            self.identity.agent.name, self.identity.agent.id
        );
        let _ = writeln!(
            out,
            "Project: {} ({})",
            self.identity.project.name, self.identity.project.id
        );
        if let Some(session) = &self.identity.session_id {
            let _ = writeln!(out, "Session: {session}");
        }
        match &self.working {
            WorkingNote::Absent => {}
            WorkingNote::Unreadable => {
                let _ = writeln!(out, "\n## Working State\n[working state unreadable]");
            }
            WorkingNote::Present { text, clipped } => {
                let _ = writeln!(out, "\n## Working State\n{text}");
                if *clipped {
                    let _ = writeln!(out, "[working state truncated]");
                }
            }
        }
        if !self.decisions.is_empty() {
            let _ = writeln!(out, "\n## Active Decisions");
            for decision in &self.decisions {
                match &decision.rationale {
                    Some(rationale) if !rationale.is_empty() => {
                        let _ = writeln!(
                            out,
                            "- {}: {} (rationale: {})",
                            decision.key, decision.statement, rationale
                        );
                    }
                    _ => {
                        let _ = writeln!(out, "- {}: {}", decision.key, decision.statement);
                    }
                }
            }
        }
        if !self.turns.is_empty() {
            let _ = writeln!(out, "\n## Recent Turns");
            for turn in &self.turns {
                let _ = writeln!(out, "[{} {}]\n{}", turn.role, turn.at, turn.text);
                if turn.clipped {
                    let _ = writeln!(out, "[turn truncated]");
                }
                out.push('\n');
            }
        }
        if !self.is_complete() {
            let _ = writeln!(
                out,
                "[truncated: context incomplete or trimmed to fit {} byte budget]",
                self.budget
            );
        }
        out
    }

    fn reduce(&mut self, excess: usize) -> bool {
        if self.turns.len() > 1 {
            self.turns.remove(0);
            self.truncated = true;
            return true;
        }
        if let WorkingNote::Present { text, clipped } = &mut self.working
            && text.len() > 256
        {
            let target = text.len().saturating_sub(excess + 32).max(256);
            if target < text.len() {
                *text = read::clip(text, target).to_owned();
                *clipped = true;
                self.truncated = true;
                return true;
            }
        }
        if !self.decisions.is_empty() {
            self.decisions.remove(0);
            self.truncated = true;
            return true;
        }
        if let Some(turn) = self.turns.first_mut()
            && turn.text.len() > 128
        {
            let target = turn.text.len().saturating_sub(excess + 32).max(128);
            if target < turn.text.len() {
                turn.text = read::clip(&turn.text, target).to_owned();
                turn.clipped = true;
                self.truncated = true;
                return true;
            }
        }
        if let WorkingNote::Present { text, clipped } = &mut self.working
            && !text.is_empty()
        {
            let target = text.len().saturating_sub(excess + 32);
            if target < text.len() {
                *text = read::clip(text, target).to_owned();
                *clipped = true;
                self.truncated = true;
                return true;
            }
        }
        if !self.turns.is_empty() {
            self.turns.remove(0);
            self.truncated = true;
            return true;
        }
        if matches!(self.working, WorkingNote::Present { .. }) {
            self.working = WorkingNote::Absent;
            self.truncated = true;
            return true;
        }
        false
    }
}

pub fn export<R: Snapshot>(input: HandoffExport, cx: &mut Cx<'_, R>) -> Result<HandoffOutput> {
    input.validate()?;
    let identity = identity::resolve_handoff(input.from.as_deref(), cx)?;
    let agent = identity.agent.id.clone();
    let (since, _resume_head, cursor) = read::checkpoint(&agent, input.since.as_ref(), cx)?;
    let mut source_incomplete = false;

    let working = match receipt::working_state_get(agent.clone(), cx)?.value {
        Read::Present { value } if !value.text.is_empty() => WorkingNote::Present {
            text: value.text,
            clipped: false,
        },
        Read::Present { .. } | Read::Absent { .. } => WorkingNote::Absent,
        Read::Unknown { .. } | Read::Unreadable { .. } => {
            source_incomplete = true;
            WorkingNote::Unreadable
        }
    };

    let (decisions, decisions_incomplete) = active_decisions(cx)?;
    if decisions_incomplete {
        source_incomplete = true;
    }

    let (turns, turns_incomplete) = committed_turns(&agent, since, cx)?;
    if turns_incomplete {
        source_incomplete = true;
    }

    let mut draft = PacketDraft {
        identity,
        working,
        decisions,
        turns,
        source_incomplete,
        truncated: false,
        budget: input.budget,
    };
    let budget = input.budget as usize;
    let text = packet::fit_handoff(
        &mut draft,
        budget,
        MAX_HANDOFF_BYTES as usize,
        PacketDraft::render,
        PacketDraft::reduce,
    )?;
    let bytes = text.len() as u64;
    let complete = draft.is_complete();
    Ok(HandoffOutput {
        agent: draft.identity.agent,
        session: draft.identity.session_id,
        text,
        bytes,
        cursor,
        complete,
    })
}

fn committed_turns<R: Snapshot>(
    agent: &AgentId,
    since: Option<se_store::StorePosition>,
    cx: &mut Cx<'_, R>,
) -> Result<(Vec<HandoffTurn>, bool)> {
    let page = cx
        .read
        .recent_turns(agent.clone(), since, read::budget(TURN_LIMIT)?)
        .map_err(|e| store_error(&e))?;
    let mut incomplete = !page.window().complete();
    let mut turns = Vec::new();
    for event in page.into_items() {
        let EventBody::SessionTurn {
            agent: target,
            text,
            role,
            ..
        } = event.body
        else {
            return Err(scope::unreadable(
                "handoff turns",
                "the targeted turn read returned another kind",
            ));
        };
        if target != *agent || event.header.scope != cx.admission.scope {
            return Err(scope::unreadable(
                "handoff turns",
                "the targeted read returned another agent or project",
            ));
        }
        let StoredText::Present(text) = text else {
            incomplete = true;
            continue;
        };
        turns.push(HandoffTurn {
            at: receipt::timestamp(event.header.occurred_at_us)?,
            role: match role {
                Role::System => "system",
                Role::User => "user",
                Role::Assistant => "assistant",
                Role::Tool => "tool",
            },
            text,
            clipped: false,
        });
    }
    Ok((turns, incomplete))
}

fn active_decisions<R: Snapshot>(cx: &mut Cx<'_, R>) -> Result<(Vec<ActiveDecision>, bool)> {
    let page = cx
        .read
        .history(
            HistoryQuery {
                agent: None,
                session: None,
                kinds: Vec::new(),
                families: vec![HistoryFamily::Decisions],
                transcript: TranscriptFilter::All,
                since: None,
                direction: HistoryDirection::OldestFirst,
            },
            read::budget(DECISION_LIMIT)?,
        )
        .map_err(|e| store_error(&e))?;
    let mut incomplete = !page.window().complete();
    let mut entries: Vec<ActiveDecision> = Vec::new();
    for event in page.into_items() {
        match event.body {
            EventBody::DecisionProposed {
                decision,
                key,
                statement,
                rationale,
                ..
            } => {
                let StoredText::Present(statement) = statement else {
                    incomplete = true;
                    continue;
                };
                let rationale = match rationale {
                    None => None,
                    Some(StoredText::Present(text)) => Some(text),
                    Some(_) => {
                        incomplete = true;
                        None
                    }
                };
                entries.push(ActiveDecision {
                    id: decision,
                    key,
                    statement,
                    rationale,
                    active: false,
                });
            }
            EventBody::DecisionRatified { decision, .. } => {
                if let Some(entry) = entries.iter_mut().find(|item| item.id == decision) {
                    entry.active = true;
                }
            }
            EventBody::DecisionRejected { decision, .. }
            | EventBody::DecisionRetracted { decision, .. } => {
                if let Some(entry) = entries.iter_mut().find(|item| item.id == decision) {
                    entry.active = false;
                }
            }
            EventBody::DecisionSuperseded {
                prior, replacement, ..
            } => {
                if let Some(entry) = entries.iter_mut().find(|item| item.id == prior) {
                    entry.active = false;
                }
                if let Some(entry) = entries.iter_mut().find(|item| item.id == replacement) {
                    entry.active = true;
                }
            }
            _ => {}
        }
    }
    entries.retain(|item| item.active);
    Ok((entries, incomplete))
}
