//! Finite target inventories share a read pin without widening snapshot visibility.
mod launch;
mod target;
use crate::{
    error::*,
    remote::{GrantState, denied, grant_at, ready},
    *,
};
pub use launch::{LaunchCandidate, SavedLaunchProfile};
use rusqlite::{Connection, OptionalExtension};
pub use target::TargetFacts;
