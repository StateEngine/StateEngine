//! Public list rows retain a counted place when their content is unreadable.
use crate::ops::{ActorRef, DecisionRow, DecisionState, DecisionStatement};
use schemars::JsonSchema;
use se_types::{DecisionId, EventId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct DecisionUnreadable {
    pub reason: String,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct UnreadableDecisionFields {
    pub id: Option<DecisionId>,
    pub key: Option<String>,
    pub state: Option<DecisionState>,
    pub governing: Option<bool>,
    pub revision: Option<u64>,
    pub statement: Option<DecisionStatement>,
    pub rationale: Option<String>,
    pub proposed_by: Option<ActorRef>,
    pub proposed_at: Option<String>,
    pub decided_by: Option<ActorRef>,
    pub decided_at: Option<String>,
    pub reason: Option<String>,
    pub supersedes: Option<DecisionId>,
    pub superseded_by: Option<DecisionId>,
    pub event_id: Option<EventId>,
}
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum DecisionPageRow {
    Present {
        #[serde(flatten)]
        row: Box<DecisionRow>,
        unreadable: Option<DecisionUnreadable>,
    },
    Unreadable {
        #[serde(flatten)]
        row: Box<UnreadableDecisionFields>,
        unreadable: DecisionUnreadable,
    },
}
