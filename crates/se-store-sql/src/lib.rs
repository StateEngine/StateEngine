//! The store's SQLite foundation: opening and configuring a connection, the
//! store header, the identity dictionary, value conversion and error mapping.
//! Event rules, reads and the writer build on it in the store.
pub mod connection;
pub mod error;
pub mod identity;
pub mod sql_value;
pub(crate) use se_store_contract::values::*;
