//! Family constructors for shared receipt declarations. These do not register
//! operations before their core planning/continuation paths are implemented.
use crate::{ops::Envelope, registry::Family};
pub use se_types::{
    AgentAction, AgentConfigReceipt, AgentOutcome, AgentReceipt, AgentReceiptValue, ConfigStorage,
    DecisionAction, DecisionReceipt, DecisionRow, DecisionState, DecisionStatement,
    NoProcessStarted, ReceiptAuthority, ReceiptGuard, WriteReceipt,
};

pub fn decision_receipt(value: DecisionReceipt) -> Envelope<DecisionReceipt> {
    Envelope::new(
        Family {
            name: "se.decision-receipt",
            major: 1,
        },
        value,
    )
}
pub fn agent_receipt(value: AgentReceipt) -> Envelope<AgentReceipt> {
    Envelope::new(
        Family {
            name: "se.agent-receipt",
            major: 1,
        },
        value,
    )
}
pub fn agent_config_receipt(value: AgentConfigReceipt) -> Envelope<AgentConfigReceipt> {
    Envelope::new(
        Family {
            name: "se.config-receipt",
            major: 1,
        },
        value,
    )
}
