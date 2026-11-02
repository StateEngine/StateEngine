//! The loopback HTTP backend for the shared MCP consumer in `crate::mcp`: the
//! bearer from the provider's protected per-launch config, rechecked by this
//! host on every call and executed through the shared router.
use crate::{HostedRouter, McpBackend, client::lease::Deadline};
use se_types::{Result, Secret};
use std::sync::Arc;

pub(crate) struct HttpBackend<'a> {
    pub router: &'a HostedRouter,
    pub deadline: &'a Deadline,
}
impl McpBackend for HttpBackend<'_> {
    async fn check_session(&mut self, capability: Arc<Secret>) -> Result<()> {
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
