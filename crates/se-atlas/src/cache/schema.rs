//! The normative STRICT/cache-only layout, including contentless record-body FTS.
use super::*;
use crate::errors::cache_error;
use rusqlite::{Connection, params};
pub const APPLICATION_ID: u32 = 0x41544c53;
pub const SCHEMA_VERSION: u32 = 4;
pub const SQL: &str = include_str!("schema.sql");
pub fn initialize(db: &Connection, seed: &CacheSeed) -> AtlasResult<()> {
    let coverage_json = serde_json::to_string(&seed.coverage).map_err(cache_error)?;
    let state_json = serde_json::to_string(&seed.state).map_err(cache_error)?;
    if seed.extractor_version.is_empty()
        || seed.extractor_version.len() > 128
        || coverage_json.len() > 4096
        || state_json.len() > 4096
    {
        return Err(cache_error("cache seed exceeds bounded metadata fields"));
    }
    db.execute_batch(SQL).map_err(cache_error)?;
    let id = &seed.identity;
    db.execute(
        "INSERT INTO meta VALUES(1,?1,?2,?3,?4,?5,?6,0,0,0,0,0,?7,?8)",
        params![
            id.scope.registration.project.as_str(),
            id.scope.registration.root.as_str(),
            id.scope.physical_root.as_slice(),
            id.epoch.as_str(),
            seed.extractor_version,
            seed.ignore_digest.0.as_slice(),
            coverage_json,
            state_json
        ],
    )
    .map_err(cache_error)?;
    db.execute("INSERT INTO record_feed VALUES(1,NULL,NULL,NULL)", [])
        .map_err(cache_error)?;
    db.pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(cache_error)?;
    db.pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(cache_error)?;
    Ok(())
}
pub fn validate(db: &Connection, id: &CacheIdentity) -> AtlasResult<()> {
    let app: u32 = db
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .map_err(cache_error)?;
    let version: u32 = db
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(cache_error)?;
    if app != APPLICATION_ID {
        return Err(cache_error("foreign application_id; preserve the cache"));
    }
    if version > SCHEMA_VERSION {
        return Err(se_types::SeError::new(
            se_types::Detail::ConfigurationInvalid(se_types::details::ConfigurationInvalid {
                subject: "Atlas cache schema".into(),
                reason: format!("schema {version} is newer than {SCHEMA_VERSION}"),
                next_step: "preserve cache bytes and upgrade se".into(),
            }),
        ));
    }
    if version != SCHEMA_VERSION {
        return Err(cache_error(
            "unsupported cache schema; explicit owned repair required",
        ));
    }
    let (project, root, physical, epoch): (String, String, Vec<u8>, String) = db
        .query_row(
            "SELECT project,root,physical_root,epoch FROM meta WHERE singleton=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .map_err(cache_error)?;
    if project != id.scope.registration.project.as_str()
        || root != id.scope.registration.root.as_str()
        || physical != id.scope.physical_root
        || epoch != id.epoch.as_str()
    {
        return Err(cache_error(
            "cache project/root/physical identity/epoch differs from registration",
        ));
    }
    Ok(())
}
/// Writers validate integrity on open/create; read opens check only the scope
/// and schema above, never a database-wide scan on the query path.
pub fn validate_integrity(db: &Connection) -> AtlasResult<()> {
    let check: String = db
        .query_row("PRAGMA quick_check(1)", [], |r| r.get(0))
        .map_err(cache_error)?;
    if check != "ok" {
        return Err(cache_error(
            "SQLite quick_check failed; preserve bytes for diagnosed repair",
        ));
    }
    Ok(())
}
