//! Native tool facts without authority, inferred edits, or tool output prose.
use se_core::ops::transcript::{Position, Record, tool::*};
use se_store::{Provider, RecordId};
use se_types::{Result, SeError, SessionId};
use sha2::{Digest, Sha256};

pub(crate) mod claude;
pub(crate) mod codex;
mod targets;
#[cfg(test)]
mod tests;

#[derive(Clone)]
pub(crate) struct Fact {
    pub key: String,
    pub native: NativeIdentity,
    pub phase: Phase,
    pub tool: ToolName,
    pub target: Target,
    pub outcome: Outcome,
}
impl Fact {
    pub fn vendor(&self, session: &SessionId) -> String {
        format!(
            "{}tool/{session}/{}",
            se_store::TRANSCRIPT_EVENT_PREFIX,
            se_types::hex_lower(&Sha256::digest(self.key.as_bytes()))
        )
    }
    pub fn record(
        &self,
        identity: &crate::SessionIdentity,
        provider: Provider,
        source: RecordId,
        position: Position,
    ) -> Result<Record> {
        let mut observation = Observation {
            schema: SCHEMA.into(),
            session: identity.session.clone(),
            agent: identity.agent.clone(),
            provider,
            source,
            position: position.clone(),
            native: self.native.clone(),
            phase: self.phase,
            tool: self.tool.clone(),
            target: self.target.clone(),
            outcome: self.outcome.clone(),
        };
        // Preserve the whole native range, never a shortened target set.
        if serde_json::to_vec(&observation).map_err(json_error)?.len() > MAX_BYTES {
            observation.target = Target::Unknown(UnknownReason::OverBudget);
        }
        let mut record = Record::new("captured-tool", None);
        record.position = position;
        record.captured_tool = Some(observation);
        Ok(record)
    }
    pub fn matches(&self, observation: &Observation) -> Result<bool> {
        let mut expected = observation.clone();
        expected.native = self.native.clone();
        expected.phase = self.phase;
        expected.tool = self.tool.clone();
        expected.target = self.target.clone();
        expected.outcome = self.outcome.clone();
        if serde_json::to_vec(&expected).map_err(json_error)?.len() > MAX_BYTES {
            expected.target = Target::Unknown(UnknownReason::OverBudget);
        }
        Ok(serde_json::to_value(expected).map_err(json_error)?
            == serde_json::to_value(observation).map_err(json_error)?)
    }
}
pub(crate) fn committed(
    fact: &Fact,
    event: se_store::StoredEvent,
    session: &SessionId,
    agent: &se_types::AgentId,
) -> Result<bool> {
    let se_store::EventBody::SessionTurn {
        session: found,
        agent: owner,
        provider: Provider::Codex,
        role: se_store::Role::System,
        vendor_ref,
        text: se_store::StoredText::Present(text),
        evidence,
        ..
    } = event.body
    else {
        return Err(SeError::invalid(
            "Codex tool acknowledgement",
            "the original canonical tool record",
        ));
    };
    let record = Record::decode(&text)?;
    record.validate_evidence(&evidence)?;
    let tool = record.captured_tool.ok_or_else(|| {
        SeError::invalid(
            "Codex tool acknowledgement",
            "the retained native observation",
        )
    })?;
    tool.validate_binding(session, agent, Provider::Codex, tool.source, &evidence)?;
    if &found != session
        || &owner != agent
        || vendor_ref != fact.vendor(session)
        || !fact.matches(&tool)?
    {
        return Err(SeError::invalid(
            "Codex tool acknowledgement",
            "unchanged canonical native facts; preserve the notification",
        ));
    }
    Ok(true)
}
fn json_error(_: serde_json::Error) -> SeError {
    SeError::invalid("captured tool", "bounded serializable native facts")
}
fn label(value: Option<&serde_json::Value>, maximum: usize) -> Option<String> {
    value
        .and_then(serde_json::Value::as_str)
        .filter(|text| {
            !text.is_empty() && text.len() <= maximum && !text.chars().any(char::is_control)
        })
        .map(str::to_owned)
}
fn tool(value: Option<&serde_json::Value>) -> ToolName {
    label(value, 128).map_or(
        ToolName::Unknown(UnknownReason::UnsupportedShape),
        ToolName::Known,
    )
}
