//! Only committed, bound native successful path tools become edit activity.
//! Prose, shell text, intents and opaque revisions never establish authorship.
use super::*;
use se_core::ops::transcript::{Record, tool::*};
use sha2::Digest;
pub(super) struct Successful(Observation);
impl Successful {
    pub fn validate_source<R: Snapshot>(&self, read: &mut R, project: &ProjectId) -> Result<()> {
        let record = scope::require_present(
            read.capture_source(self.0.source)
                .map_err(|e| store_error(&e))?,
            "captured tool source",
            "Restore the committed source binding before indexing its activity.",
        )?;
        let original = record
            .original
            .map(|event| *event)
            .unwrap_or(record.current);
        if original.header.scope != Scope::Project(project.clone())
            || !matches!(original.body,EventBody::CaptureSource{source,session,..} if source==self.0.source && session==self.0.session)
        {
            return Err(SeError::invalid(
                "captured tool source",
                "the same committed project and session binding",
            ));
        }
        Ok(())
    }
    pub fn paths(&self) -> &[ObservedPath] {
        match &self.0.target {
            Target::Paths(paths) => paths,
            _ => &[],
        }
    }
    pub fn key(&self) -> Result<RecordKey> {
        let identity = (
            &self.0.session,
            self.0.source,
            self.0.provider,
            &self.0.native,
            self.0.phase,
            &self.0.position,
        );
        let digest = sha2::Sha256::digest(
            serde_json::to_vec(&identity)
                .map_err(|e| SeError::invalid("captured tool identity", &e.to_string()))?,
        );
        RecordKey::new(format!("tool:{digest:x}"))
    }
    pub fn actor(&self) -> AtlasActor {
        AtlasActor {
            principal: AtlasPrincipal::Agent(self.0.agent.clone()),
            name: self.0.agent.to_string(),
        }
    }
    pub fn description(&self) -> String {
        "Captured native file edit succeeded; current-content author unknown".into()
    }
}
pub(super) enum Captured {
    Match(Box<Successful>),
    Skip,
    Oversized(usize),
}

pub(super) fn successful(event: &StoredEvent) -> Result<Captured> {
    let EventBody::SessionTurn {
        session,
        agent,
        provider,
        vendor_ref,
        role: se_store::Role::System,
        text: StoredText::Present(text),
        evidence,
        ..
    } = &event.body
    else {
        return Ok(Captured::Skip);
    };
    if !vendor_ref.starts_with(se_store::TRANSCRIPT_EVENT_PREFIX) {
        return Ok(Captured::Skip);
    }
    if text.len() > 8192 {
        return Ok(Captured::Oversized(text.len()));
    }
    let metadata = Record::decode(text)?;
    if metadata.kind != "captured-tool" {
        return Ok(Captured::Skip);
    }
    if metadata.kind_truncated || metadata.subtype_truncated {
        return Err(SeError::invalid(
            "captured metadata",
            "untruncated native metadata labels",
        ));
    }
    metadata.validate_evidence(evidence)?;
    let tool = metadata.captured_tool.ok_or_else(|| {
        SeError::invalid("captured metadata", "the retained native tool observation")
    })?;
    tool.validate_binding(session, agent, *provider, tool.source, evidence)?;
    const EDIT_TOOLS: &str =
        "Edit Write MultiEdit apply_patch FileChange fileChange file_change write_file edit_file";
    let ToolName::Known(name) = &tool.tool else {
        return Ok(Captured::Skip);
    };
    if !matches!(tool.phase, Phase::Completed)
        || !matches!(tool.outcome, Outcome::Succeeded)
        || matches!(tool.native, NativeIdentity::Unknown(_))
        || !matches!(tool.target, Target::Paths(_))
        || !EDIT_TOOLS.split(' ').any(|t| t == name)
    {
        return Ok(Captured::Skip);
    }
    Ok(Captured::Match(Box::new(Successful(tool))))
}
