//! Remote CLI client dispatch, native Owner controls, and pairing presentation.
pub mod client;

#[cfg(feature = "remote")]
use clap::ArgMatches;
#[cfg(feature = "remote")]
use se_host::remote::OwnerInput;
#[cfg(feature = "remote")]
use se_types::{IdempotencyKey, Result};
#[cfg(feature = "remote")]
use std::io::{self, Write};

#[cfg(feature = "remote")]
mod grammar;
#[cfg(feature = "remote")]
mod init;
#[cfg(feature = "remote")]
mod launch_permissions;
#[cfg(feature = "remote")]
mod owner;
#[cfg(feature = "remote")]
mod pair;
#[cfg(feature = "remote")]
mod permissions;
#[cfg(feature = "remote")]
mod ports;
#[cfg(feature = "remote")]
mod progress;
#[cfg(feature = "remote")]
mod source_permissions;

#[cfg(feature = "remote")]
pub use init::{derive_alias, parse_remote_spec, validate_agent_name, validate_remote_path};
#[cfg(feature = "remote")]
pub use owner::{Input, entry, help};
#[cfg(feature = "remote")]
use owner::{invalid, required, text};
#[cfg(feature = "remote")]
pub use ports::{OwnerCommands, Presentation};
