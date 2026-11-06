//! Only committed, bound native successful path tools become edit activity.
//! Prose, shell text, intents and opaque revisions never establish authorship.
use super::*;
use crate::ops::transcript::{Record, tool::*};
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
pub(super) fn successful(event: &StoredEvent) -> Result<Option<Successful>> {
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
        return Ok(None);
    };
    if !vendor_ref.starts_with(se_store::TRANSCRIPT_EVENT_PREFIX) {
        return Ok(None);
    }
    // Native metadata is already bounded by capture. Avoid parsing arbitrary
    // chat or scanning bodies for tool-looking strings.
    if text.len() > 8192 {
        return Err(SeError::too_large("captured metadata", 8192, text.len()));
    }
    let metadata = Record::decode(text)?;
    if metadata.kind != "captured-tool" {
        return Ok(None);
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
    if !matches!(tool.phase, Phase::Completed)
        || !matches!(tool.outcome, Outcome::Succeeded)
        || matches!(tool.native, NativeIdentity::Unknown(_))
        || !matches!(tool.target, Target::Paths(_))
    {
        return Ok(None);
    }
    let ToolName::Known(name) = &tool.tool else {
        return Ok(None);
    };
    if !matches!(
        name.as_str(),
        "Edit"
            | "Write"
            | "MultiEdit"
            | "apply_patch"
            | "FileChange"
            | "fileChange"
            | "file_change"
            | "write_file"
            | "edit_file"
    ) {
        return Ok(None);
    }
    Ok(Some(Successful(tool)))
}
