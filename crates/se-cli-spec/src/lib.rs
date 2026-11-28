//! CLI grammar, argument decoding, help rendering, and built-in guide topics.
//! Separated from `se-core` so the sans-IO core kernel carries no `clap` or prose.
pub mod cli;
pub mod guide;
mod meta;

pub use cli::{
    CommonArgs, cli_command, from_matches, from_matches_with_key, output_global_args,
    parse_remote_target, selected_meta,
};
pub use meta::metadata_output;
pub use se_core::ops::{AgentCommand, CliSelections, command_name, diagnostic_word};
