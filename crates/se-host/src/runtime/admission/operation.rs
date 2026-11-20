use super::super::start::allocate_facts;
use super::{AdmissionContext, Pending, remote_credential};
use crate::runtime::{HostedCall, HostedInput};
use se_core::{admission::HumanTerminal, ops, store_error::store_error};
use se_store::{Actor, Scope};
use se_types::{Result, SeError};
impl AdmissionContext {
    /// MCP over loopback HTTP: a current session bearer only. This transport has
    /// no owner proof, launch activation or per-call authority override (§7.3).
    /// The shared consumer has already decoded the tool through core's registry.
    pub fn with_mcp_call<T>(
        &self,
        secret: &se_types::Secret,
        operation: ops::AnyOp,
        finish: impl FnOnce(se_store::ReadPhase, HostedCall) -> Result<T>,
    ) -> Result<T> {
        let phase = self.reads.read_phase().map_err(|e| store_error(&e))?;
        let result = (|| {
            self.check_generation(&phase)?;
            let admission = self.credential(&phase, secret, crate::MCP_BEARER_PURPOSE)?;
            se_core::admission::authorize(operation.meta(), &admission)?;
            let mut facts = allocate_facts()?;
            facts.door = se_store::Door::Mcp;
            let remote_credential = operation
                .is_remote()
                .then(|| remote_credential(&phase, secret))
                .transpose()?;
            Ok(HostedCall {
                remote_credential,
                input: HostedInput::Operation(operation),
                kernel: self.kernel(facts)?,
                admission,
                terminal: HumanTerminal::Refused {
                    reason: "session authority cannot become an owner terminal".into(),
                },
                selections: None,
            })
        })();
        match result {
            Ok(call) => finish(phase, call),
            Err(error) => super::super::executor::close_read(Err(error), phase.close()),
        }
    }
    pub fn mcp_principal(&self, secret: &se_types::Secret) -> Result<crate::mcp::McpPrincipal> {
        let phase = self.reads.read_phase().map_err(|e| store_error(&e))?;
        let result = (|| {
            self.check_generation(&phase)?;
            let admission = self.credential(&phase, secret, crate::MCP_BEARER_PURPOSE)?;
            match (admission.scope, admission.actor) {
                (Scope::Project(project), Actor::Agent(agent)) => Ok(crate::mcp::McpPrincipal {
                    project,
                    agent: Some(agent),
                }),
                _ => Err(SeError::invalid(
                    "MCP caller",
                    "an authenticated agent in its bound project",
                )),
            }
        })();
        super::super::executor::close_read(result, phase.close())
    }
    /// Read-only MCP methods still require the same current session bearer.
    pub fn check_session(&self, secret: &se_types::Secret) -> Result<()> {
        let phase = self.reads.read_phase().map_err(|e| store_error(&e))?;
        let result = (|| {
            self.check_generation(&phase)?;
            self.credential_in(&phase, secret, crate::MCP_BEARER_PURPOSE, Pending::Discover)
                .map(drop)
        })();
        super::super::executor::close_read(result, phase.close())
    }
    pub(super) fn kernel(
        &self,
        facts: se_core::dispatch::CallFacts,
    ) -> Result<se_core::dispatch::Kernel> {
        let kernel =
            se_core::dispatch::Kernel::new(facts)?.with_command_home(&self.state_directory);
        match &self.configuration {
            Some(configuration) => {
                let mut kernel = kernel.with_configuration(configuration.clone())?;
                if let Some(file) = &self.configuration_file {
                    kernel = kernel.with_config_origin(format!("config.toml {}", file.display()));
                }
                Ok(kernel)
            }
            None => Ok(kernel),
        }
    }
}
