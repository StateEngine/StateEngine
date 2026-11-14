//! Native distribution discovery and fixed image staging commands.
mod distribution;
pub(super) use distribution::{Image, describe};
pub(super) mod staging;
pub(super) mod transactions;
