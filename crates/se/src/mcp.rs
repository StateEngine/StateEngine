//! Installed MCP stdio entry. The common se-host consumer owns JSON-RPC;
//! this adapter owns pipe I/O and the persistent session-only native client.
mod backend;
mod external;
use se_types::Result;
use std::ffi::OsString;

pub fn entry(args: &[OsString]) -> Option<Result<u8>> {
    // Absence of the literal transport command is enough to skip this parse.
    // A present token still goes through the generated grammar, so option
    // values named "mcp" cannot select a transport or bypass validation.
    if !args.iter().skip(1).any(|arg| arg == "mcp") {
        return None;
    }
    crate::grammar::mcp_options(args).map(|options| options.and_then(run))
}
fn run(options: crate::grammar::McpOptions) -> Result<u8> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| se_core::scope::unreadable("MCP runtime", &error.to_string()))?;
    if let Some(agent) = options.external_as {
        let mut backend = external::ExternalBackend::connect(options.home, agent, options.project)?;
        return crate::mcp_stdio::serve(|bytes| {
            Ok(
                match runtime.block_on(se_host::mcp::dispatch(bytes, None, &mut backend)) {
                    se_host::McpReply::Json(value) => Some(value),
                    se_host::McpReply::Accepted => None,
                },
            )
        });
    }
    let mut backend = backend::Backend::new(options.home);
    crate::mcp_stdio::serve(|bytes| {
        Ok(
            match runtime.block_on(se_host::mcp::dispatch(bytes, None, &mut backend)) {
                se_host::McpReply::Json(value) => Some(value),
                se_host::McpReply::Accepted => None,
            },
        )
    })
}
