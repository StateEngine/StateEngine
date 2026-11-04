//! Loopback HTTP surface of a running host: POST /mcp for launched provider
//! sessions and anonymous GET /stateengine/livez (section 40 §7.3). HTTP never
//! accepts owner authority; the session bearer is the only credential. MCP
//! protocol handling itself is the shared consumer in `crate::mcp`.
mod admission;
pub(crate) mod mail;
mod mcp;
pub(crate) mod proof;
mod server;
pub use server::HttpListener;
pub(crate) use server::connection;
