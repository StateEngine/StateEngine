//! Optional typed code context. Assembly cannot consume the private resume cursor.
use crate::{
    ops::continuity::{ResumeOutput, SessionContextOutput, packet::wire_bytes},
    scope,
};
use se_store::{Admission, atlas_resume::AtlasResumeMutation};
use se_types::{AgentId, EventId, ProjectId, Result, SeError, code::*};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct Section {
    code_changes: Vec<ResumeChange>,
    code_status: ResumeCodeStatus,
}
/// Retained only by a delivery-capable adapter; never part of model input.
pub struct CodeDelivery {
    project: ProjectId,
    viewer: AgentId,
    root: RootId,
    epoch: CacheEpoch,
    advance: ResumeAdvance,
    section_sha256: [u8; 32],
}
impl CodeDelivery {
    /// Call after successful delivery of the retained section. An unacknowledged
    /// consumer drops this token and repeats the summary on its next read.
    pub fn delivered(self, admission: Admission, delivery: EventId) -> Result<AtlasResumeMutation> {
        if admission.scope != se_store::Scope::Project(self.project)
            || admission.actor != se_store::Actor::Agent(self.viewer.clone())
            || admission.session.is_none()
        {
            return Err(SeError::invalid(
                "code context delivery",
                "the verified project, viewer and session",
            ));
        }
        Ok(AtlasResumeMutation::Delivered {
            admission,
            root: self.root,
            epoch: self.epoch,
            viewer: self.viewer,
            delivery,
            section_sha256: self.section_sha256,
            advance: self.advance,
        })
    }
}
struct Prepared {
    section: Section,
    advance: Option<ResumeAdvance>,
    retrieval: Option<AtlasCursor>,
    project: ProjectId,
    viewer: AgentId,
    root: Option<RootId>,
    epoch: Option<CacheEpoch>,
}
impl Prepared {
    fn new(source: ResumeCode, project: &ProjectId, viewer: &AgentId) -> Result<Self> {
        if &source.index.project != project || source.items.len() > 5 {
            return Err(SeError::invalid(
                "code context",
                "the admitted project and at most five file groups",
            ));
        }
        let mut retrieval = source.omitted_since.clone();
        if let Some(advance) = &source.advance {
            let epoch = source
                .index
                .epoch
                .as_ref()
                .ok_or_else(|| cursor_invalid("offer has no epoch"))?;
            let principal = AtlasPrincipal::Agent(viewer.clone());
            let upper = CodeCursorPosition::decode(&advance.next_cursor)?.resume_fence(
                project,
                &source.index.root,
                epoch,
                &principal,
            )?;
            if upper != advance.fence.0 {
                return Err(cursor_invalid("offer and saved fence differ"));
            }
            if let Some(old) = &advance.expected_cursor {
                let lower = CodeCursorPosition::decode(old)?.resume_fence(
                    project,
                    &source.index.root,
                    epoch,
                    &principal,
                )?;
                if lower > upper {
                    return Err(cursor_invalid("offer moves backwards"));
                }
                if retrieval.is_none() {
                    retrieval = Some(
                        CodeCursorPosition::new(
                            &source.index,
                            "changes-range",
                            cursor_digest(&("changes-range", &principal))?,
                            CursorKey {
                                integers: vec![lower, u64::from(u32::MAX)],
                                bytes: vec![],
                            },
                            Some(advance.fence),
                        )?
                        .encode()?,
                    );
                }
            }
        }
        let advance = if matches!(
            source.state,
            ResumeCodeState::BudgetExceeded
                | ResumeCodeState::Disabled
                | ResumeCodeState::NeverIndexed
                | ResumeCodeState::Unreadable
        ) {
            None
        } else {
            source.advance
        };
        Ok(Self {
            section: Section {
                code_changes: source.items,
                code_status: ResumeCodeStatus {
                    state: source.state,
                    complete: source.complete,
                    omitted: source.omitted,
                    unattributed_omitted: source.unattributed_omitted,
                    omitted_since: source.omitted_since,
                },
            },
            advance,
            retrieval,
            project: project.clone(),
            viewer: viewer.clone(),
            root: Some(source.index.root),
            epoch: source.index.epoch,
        })
    }
    fn status(project: ProjectId, viewer: AgentId, state: ResumeCodeState) -> Self {
        Self {
            section: Section {
                code_changes: Vec::new(),
                code_status: ResumeCodeStatus {
                    state,
                    complete: false,
                    omitted: None,
                    unattributed_omitted: None,
                    omitted_since: None,
                },
            },
            advance: None,
            retrieval: None,
            project,
            viewer,
            root: None,
            epoch: None,
        }
    }
    fn fit(&mut self, limit: usize) -> Result<bool> {
        loop {
            if !self.section.code_status.complete
                && matches!(
                    self.section.code_status.state,
                    ResumeCodeState::Available
                        | ResumeCodeState::Zero
                        | ResumeCodeState::BaselineGap
                        | ResumeCodeState::Updating
                )
            {
                self.section.code_status.omitted_since = self.retrieval.clone();
                if self.retrieval.is_none() {
                    self.exceeded();
                }
            }
            if encode(&self.section)?.len() <= limit.min(600) {
                return Ok(true);
            }
            if self.section.code_changes.pop().is_some() {
                let status = &mut self.section.code_status;
                status.complete = false;
                status.omitted = status.omitted.map(|n| n.saturating_add(1));
            } else if self.advance.is_some() || self.section.code_status.omitted_since.is_some() {
                self.exceeded();
            } else {
                return Ok(false);
            }
        }
    }
    fn exceeded(&mut self) {
        self.section.code_changes.clear();
        self.section.code_status = ResumeCodeStatus {
            state: ResumeCodeState::BudgetExceeded,
            complete: false,
            omitted: None,
            unattributed_omitted: None,
            omitted_since: None,
        };
        self.advance = None;
    }
    fn delivery(self) -> Result<Option<CodeDelivery>> {
        let Some(mut advance) = self.advance else {
            return Ok(None);
        };
        let section_sha256: [u8; 32] = Sha256::digest(encode(&self.section)?).into();
        // Core can omit additional whole items. Distinct retained sections are
        // distinct offers, so concurrent allocations return Stale rather than
        // colliding with a replay of a different delivered section.
        let offer = Sha256::digest(encode(&(advance.offer, section_sha256))?);
        advance.offer.0.copy_from_slice(&offer[..16]);
        let epoch = self
            .epoch
            .ok_or_else(|| cursor_invalid("offered epoch absent"))?;
        Ok(Some(CodeDelivery {
            project: self.project,
            viewer: self.viewer,
            root: self
                .root
                .ok_or_else(|| cursor_invalid("offered root absent"))?,
            epoch,
            advance,
            section_sha256,
        }))
    }
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>> {
    serde_json::to_vec(value)
        .map_err(|e| scope::unreadable("code context encoding", &e.to_string()))
}

/// Add code using only space left by the already assembled private context.
/// None means no acknowledged cursor advance, including a wholly omitted section.
pub fn attach_resume(
    output: &mut ResumeOutput,
    source: ResumeCode,
    allocation: u32,
) -> Result<Option<CodeDelivery>> {
    if output.code_changes.is_some() || output.code_status.is_some() {
        return Err(SeError::invalid(
            "code context",
            "one attachment per packet",
        ));
    }
    let prepared = Prepared::new(
        source,
        &output.principal.project.id,
        &output.principal.agent.id,
    )?;
    attach_resume_prepared(output, prepared, allocation)
}
pub fn attach_resume_status(
    output: &mut ResumeOutput,
    state: ResumeCodeState,
    allocation: u32,
) -> Result<()> {
    let prepared = Prepared::status(
        output.principal.project.id.clone(),
        output.principal.agent.id.clone(),
        state,
    );
    attach_resume_prepared(output, prepared, allocation).map(|_| ())
}
fn attach_resume_prepared(
    output: &mut ResumeOutput,
    mut prepared: Prepared,
    allocation: u32,
) -> Result<Option<CodeDelivery>> {
    if output.code_changes.is_some() || output.code_status.is_some() {
        return Err(SeError::invalid(
            "code context",
            "one attachment per packet",
        ));
    }
    if output.principal.preview || output.principal.session_id.is_none() {
        prepared.advance = None;
    }
    let was_complete = output.complete;
    let base = wire_bytes("se.resume/v1", output)?;
    let mut limit = usize::min(
        allocation as usize,
        (output.budget.limit_bytes as usize).saturating_sub(base),
    );
    loop {
        if !prepared.fit(limit)? {
            return Ok(None);
        }
        output.complete = was_complete && prepared.section.code_status.complete;
        output.code_changes = Some(prepared.section.code_changes.clone());
        output.code_status = Some(prepared.section.code_status.clone());
        for _ in 0..8 {
            let bytes = wire_bytes("se.resume/v1", output)?;
            if bytes as u64 == output.budget.used_bytes {
                break;
            }
            output.budget.used_bytes = bytes as u64;
        }
        let bytes = wire_bytes("se.resume/v1", output)?;
        if bytes <= output.budget.limit_bytes as usize {
            return prepared.delivery();
        }
        output.code_changes = None;
        output.code_status = None;
        output.complete = was_complete;
        limit = limit.saturating_sub(bytes - output.budget.limit_bytes as usize + 1);
        output.budget.used_bytes = base as u64;
    }
}

/// The linked session consumer gets the same typed array in its actual model input.
pub fn attach_context(
    output: &mut SessionContextOutput,
    source: ResumeCode,
    byte_budget: u32,
    allocation: u32,
) -> Result<Option<CodeDelivery>> {
    let prepared = Prepared::new(source, &output.project_id, &output.agent_id)?;
    attach_context_prepared(output, prepared, byte_budget, allocation)
}
pub fn attach_context_status(
    output: &mut SessionContextOutput,
    state: ResumeCodeState,
    byte_budget: u32,
    allocation: u32,
) -> Result<()> {
    let prepared = Prepared::status(output.project_id.clone(), output.agent_id.clone(), state);
    attach_context_prepared(output, prepared, byte_budget, allocation).map(|_| ())
}
fn attach_context_prepared(
    output: &mut SessionContextOutput,
    mut prepared: Prepared,
    byte_budget: u32,
    allocation: u32,
) -> Result<Option<CodeDelivery>> {
    let base = wire_bytes("secode.session-context-v1", output)?;
    let mut limit = usize::min(
        allocation as usize,
        (byte_budget as usize).saturating_sub(base),
    );
    let original = &output.assembled_model_input;
    let mut state: serde_json::Value = serde_json::from_str(original)
        .map_err(|e| scope::unreadable("session context model input", &e.to_string()))?;
    let object = state
        .as_object_mut()
        .ok_or_else(|| scope::unreadable("session context model input", "object required"))?;
    if object.contains_key("code_changes") || object.contains_key("code_status") {
        return Err(SeError::invalid(
            "code context",
            "one attachment per packet",
        ));
    }
    loop {
        if !prepared.fit(limit)? {
            return Ok(None);
        }
        let section = serde_json::to_value(&prepared.section)
            .map_err(|e| scope::unreadable("code context", &e.to_string()))?;
        for (key, value) in section
            .as_object()
            .ok_or_else(|| scope::unreadable("code context", "object required"))?
        {
            state[key] = value.clone();
        }
        let text = serde_json::to_string(&state)
            .map_err(|e| scope::unreadable("session context model input", &e.to_string()))?;
        let old_text = std::mem::replace(&mut output.assembled_model_input, text);
        let old_id = std::mem::replace(
            &mut output.packet_id,
            format!(
                "{:x}",
                Sha256::digest(output.assembled_model_input.as_bytes())
            ),
        );
        let old_size = output.byte_size;
        let was_truncated = output.truncated;
        output.truncated |= !prepared.section.code_status.complete;
        output.byte_size = output.assembled_model_input.len() as u64;
        let bytes = wire_bytes("secode.session-context-v1", output)?;
        if bytes <= byte_budget as usize {
            return prepared.delivery();
        }
        output.assembled_model_input = old_text;
        output.packet_id = old_id;
        output.byte_size = old_size;
        output.truncated = was_truncated;
        limit = limit.saturating_sub(bytes - byte_budget as usize + 1);
    }
}

/// Native consumers budget their raw model input directly, without a CLI envelope.
/// A source failure still produces a bounded typed status; no offer is invented.
pub fn attach_model_input(
    text: &mut String,
    source: std::result::Result<ResumeCode, ResumeCodeState>,
    project: &ProjectId,
    viewer: &AgentId,
    byte_budget: u32,
    allocation: u32,
) -> Result<Option<CodeDelivery>> {
    let mut prepared = match source {
        Ok(source) => Prepared::new(source, project, viewer)?,
        Err(state) => Prepared::status(project.clone(), viewer.clone(), state),
    };
    let mut model: serde_json::Value = serde_json::from_str(text)
        .map_err(|e| scope::unreadable("native model input", &e.to_string()))?;
    let object = model
        .as_object_mut()
        .ok_or_else(|| scope::unreadable("native model input", "object required"))?;
    if object.contains_key("code_changes") || object.contains_key("code_status") {
        return Err(SeError::invalid(
            "code context",
            "one attachment per packet",
        ));
    }
    let mut limit = (allocation as usize).min((byte_budget as usize).saturating_sub(text.len()));
    loop {
        if !prepared.fit(limit)? {
            return Ok(None);
        }
        object.insert(
            "code_changes".into(),
            serde_json::to_value(&prepared.section.code_changes)
                .map_err(|e| scope::unreadable("code changes", &e.to_string()))?,
        );
        object.insert(
            "code_status".into(),
            serde_json::to_value(&prepared.section.code_status)
                .map_err(|e| scope::unreadable("code status", &e.to_string()))?,
        );
        let encoded = serde_json::to_string(&object)
            .map_err(|e| scope::unreadable("native model input", &e.to_string()))?;
        if encoded.len() <= byte_budget as usize {
            *text = encoded;
            return prepared.delivery();
        }
        limit = limit.saturating_sub(encoded.len() - (byte_budget as usize) + 1);
    }
}
