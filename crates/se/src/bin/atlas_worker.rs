//! The dedicated Atlas cold worker image.
//!
//! This binary runs only the private worker entry; it is never a public
//! command, an agent session or an MCP server. Because it references none of
//! the CLI surface, the linker keeps the CLI's optional features out of the
//! address space the worker's cold containment limits cover.
fn main() -> std::process::ExitCode {
    se_host::atlas_worker::worker_main()
}
