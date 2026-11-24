//! Host side of agent observation. The protected machine identity is read
//! through this crate's state files and handed to the observation crate.
use se_agent_observation::{AgentObservation, AgentObservationPlan};
use se_types::{MachineId, Result, SeError};
use std::{path::Path, time::Instant};

pub fn observe_agent(plan: AgentObservationPlan, deadline: Instant) -> Result<AgentObservation> {
    se_agent_observation::observe_agent(plan, deadline, machine_identity)
}

pub(crate) fn machine_identity(home: &Path) -> Result<MachineId> {
    let files = crate::state_files::Files::open(home)
        .map_err(|e| SeError::invalid("agent session observation", &e.to_string()))?;
    crate::state_files::machine_identity(&files)
}
