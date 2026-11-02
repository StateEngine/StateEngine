//! Installed MCP stdio entry. The common se-host consumer owns JSON-RPC;
//! this adapter owns pipe I/O and the persistent session-only native client.
mod backend;
use se_types::Result;
use std::ffi::OsString;

pub fn entry(args: &[OsString]) -> Option<Result<u8>> {
    crate::grammar::mcp_options(args).map(|home| home.and_then(run))
}
fn run(home: Option<std::path::PathBuf>) -> Result<u8> {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()
        .map_err(|error| se_core::scope::unreadable("MCP runtime", &error.to_string()))?;
    let mut backend = backend::Backend::new(home);
    crate::mcp_stdio::serve(|bytes| {
        Ok(match runtime.block_on(se_host::mcp::dispatch(bytes, None, &mut backend)) {
            se_host::McpReply::Json(value) => Some(value),
            se_host::McpReply::Accepted => None,
        })
    })
}
