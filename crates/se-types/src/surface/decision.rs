use super::{ActorRef, Named, ReceiptAuthority, WriteReceipt};
use crate::{DecisionId, EventId, ProjectId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DecisionState {
    Pending,
    Ratified,
    Rejected,
    Retracted,
    Superseded,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DecisionAction {
    Propose,
    Ratify,
    Reject,
    Retract,
    Supersede,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DecisionStatement {
    pub text: String,
    pub complete: bool,
    pub bytes: u64,
    pub command: Option<String>,
    pub argv: Option<Vec<String>>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DecisionRow {
    pub id: DecisionId,
    pub key: String,
    pub state: DecisionState,
    pub governing: bool,
    pub revision: u64,
    pub statement: DecisionStatement,
    pub rationale: Option<String>,
    pub proposed_by: ActorRef,
    pub proposed_at: String,
    pub decided_by: Option<ActorRef>,
    pub decided_at: Option<String>,
    pub reason: Option<String>,
    pub supersedes: Option<DecisionId>,
    pub superseded_by: Option<DecisionId>,
    pub event_id: EventId,
}
/// se.decision-receipt/v1 payload. Supersede returns the governing replacement
/// in decision and the superseded predecessor in replaced, atomically.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DecisionReceipt {
    #[serde(flatten)]
    pub commit: WriteReceipt,
    pub authority: ReceiptAuthority,
    pub action: DecisionAction,
    pub project: Named<ProjectId>,
    pub decision: DecisionRow,
    pub replaced: Option<DecisionRow>,
}
