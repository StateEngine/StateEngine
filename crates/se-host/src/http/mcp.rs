//! The loopback HTTP backend for the shared MCP consumer in `crate::mcp`: the
//! bearer from the provider's protected per-launch config, rechecked by this
//! host on every call and executed through the shared router.
use crate::{HostedRouter, McpBackend, client::lease::Deadline};
use se_types::{Result, Secret};
use std::{sync::Arc, time::Duration};

pub(crate) struct HttpBackend<'a> {
    pub router: &'a HostedRouter,
    pub deadline: &'a Deadline,
    /// The Authorization header was present but not a readable bearer.
    pub malformed: bool,
    pub session_proof: Option<Arc<Secret>>,
    pub malformed_proof: bool,
}
impl HttpBackend<'_> {
    async fn active_principal(
        &mut self,
        capability: Arc<Secret>,
    ) -> Result<crate::mcp::McpPrincipal> {
        if self.session_proof.is_none() && !self.malformed_proof {
            return self.router.mcp_principal(capability, self.deadline).await;
        }
        // The verified first-use handshake lets launch finish preparing. A
        // provider's first tool request can arrive before activation commits;
        // hold that request within its original budget, without executing it.
        loop {
            self.check_session(Arc::clone(&capability)).await?;
            match self
                .router
                .mcp_principal(Arc::clone(&capability), self.deadline)
                .await
            {
                Err(error)
                    if matches!(error.body.detail(), se_types::Detail::SessionNotActive(_)) =>
                {
                    // Each read is closed before yielding, and the next pass
                    // revalidates both purposes, scope and activation state.
                    tokio::time::sleep(self.deadline.remaining()?.min(Duration::from_millis(25)))
                        .await;
                }
                result => return result,
            }
        }
    }
}
impl McpBackend for HttpBackend<'_> {
    async fn witness_initialization(&mut self, supplied: Option<Arc<Secret>>) -> Result<()> {
        if self.session_proof.is_none() && !self.malformed_proof {
            return Ok(());
        }
        let capability = self.capability(None, supplied)?.ok_or_else(|| {
            se_types::SeError::invalid(
                "session first-use proof",
                "both the HTTP bearer and session proof from the same launch",
            )
        })?;
        // The existing pair verifier records both actual request witnesses only
        // after checking their scope, purposes, generation and activation state.
        // It admits no tool operation and does not activate either credential.
        self.check_session(capability).await
    }
    /// HTTP's capability is only its bearer; a malformed header never falls
    /// back to anonymous for a tool method or an explicit initialization pair.
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
        if self.session_proof.is_some() || self.malformed_proof {
            self.active_principal(Arc::clone(&capability)).await?;
        }
        self.router
            .mcp_call(capability, operation, self.deadline)
            .await
            .map(|output| output.value)
    }
    async fn atlas_available(&mut self, capability: Arc<Secret>) -> Result<bool> {
        self.check_session(capability).await?;
        Ok(self.router.execution.atlas.is_installed())
    }
    async fn bound_principal(
        &mut self,
        capability: Arc<Secret>,
    ) -> Result<crate::mcp::McpPrincipal> {
        self.active_principal(capability).await
    }
    fn response_limit(&self) -> usize {
        self.router.response_limit().get() as usize
    }
}
