//! The loopback HTTP backend for the shared MCP consumer in `crate::mcp`: the
//! bearer from the provider's protected per-launch config, rechecked by this
//! host on every call and executed through the shared router.
use crate::{HostedRouter, McpBackend, client::lease::Deadline};
use se_types::{Result, Secret};
use std::sync::Arc;

pub(crate) struct HttpBackend<'a> {
    pub router: &'a HostedRouter,
    pub deadline: &'a Deadline,
    /// The Authorization header was present but not a readable bearer.
    pub malformed: bool,
    pub session_proof: Option<Arc<Secret>>,
    pub malformed_proof: bool,
}
impl McpBackend for HttpBackend<'_> {
    /// HTTP's capability is only its bearer; a malformed header never falls
    /// back to anonymous for a tool method.
    fn capability(
        &mut self,
        _metadata: Option<&serde_json::Value>,
        supplied: Option<Arc<Secret>>,
    ) -> Result<Option<Arc<Secret>>> {
        if self.malformed {
            return Err(se_types::SeError::invalid(
                "Authorization",
                "a well-formed `Bearer <session capability>` header",
            ));
        }
        Ok(supplied)
    }
    async fn check_session(&mut self, capability: Arc<Secret>) -> Result<()> {
        if self.malformed_proof {
            return Err(se_types::SeError::invalid(
                "session first-use proof",
                "one well-formed separately issued session capability",
            ));
        }
        if let Some(pin) = &self.session_proof {
            return self
                .router
                .codex_discovery(capability, Arc::clone(pin), self.deadline)
                .await;
        }
        self.router.check_session(capability, self.deadline).await
    }
    async fn call(
        &mut self,
        capability: Arc<Secret>,
        operation: se_core::ops::AnyOp,
    ) -> Result<serde_json::Value> {
        self.router
            .mcp_call(capability, operation, self.deadline)
            .await
            .map(|output| output.value)
    }
    fn response_limit(&self) -> usize {
        self.router.response_limit().get() as usize
    }
}
