//! Event facts: the closed JSON form each committed event stores beside its
//! typed columns. Pure over contract types; reading and writing rows, and the
//! payload text kept in its own column, stay in the store.
pub mod cursor;
pub mod import;
pub mod maintenance;
mod metadata;
mod semantic;
pub use metadata::metadata;
use se_store_contract::{error::fail, *};
pub use semantic::descriptor;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

/// Payload text a decoder names by field; the store reads it from its column.
pub type Text<'a> = &'a mut dyn FnMut(&str) -> StoreResult<StoredText>;
pub fn invalid(e: impl std::fmt::Display) -> Box<StoreError> {
    fail(StoreErrorCode::EventInvalid, e.to_string())
}
pub fn encode<T: Serialize>(v: &T) -> StoreResult<String> {
    serde_json::to_string(v).map_err(invalid)
}
pub fn field<T: DeserializeOwned>(v: &Value, k: &str) -> StoreResult<T> {
    serde_json::from_value(
        v.get(k)
            .cloned()
            .ok_or_else(|| invalid(format!("missing stored field {k}")))?,
    )
    .map_err(invalid)
}
