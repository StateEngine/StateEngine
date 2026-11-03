use crate::{error::*, *};
use rusqlite::{Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use uuid::{Builder, Uuid, Variant, Version};
impl RecordIdentity for RecordId {
    fn from_parts(time: u64, random: [u8; 10]) -> StoreResult<Self> {
        if time > 0xffff_ffff_ffff {
            return Err(invalid("record timestamp exceeds UUIDv7 range"));
        }
        Self::from_bytes(
            *Builder::from_unix_timestamp_millis(time, &random)
                .into_uuid()
                .as_bytes(),
        )
    }
    fn from_bytes(bytes: [u8; 16]) -> StoreResult<Self> {
        let id = Uuid::from_bytes(bytes);
        if id.get_version() != Some(Version::SortRand) || id.get_variant() != Variant::RFC4122 {
            return Err(invalid("record identity requires RFC UUIDv7"));
        }
        Ok(Self::new_internal(bytes))
    }
    fn as_bytes(&self) -> &[u8; 16] {
        self.bytes_internal()
    }
}
impl Actor {
    pub(crate) fn wire(&self) -> &str {
        match self {
            Self::Human(x) => x.as_str(),
            Self::Agent(x) => x.as_str(),
        }
    }
    pub(crate) fn kind(&self) -> &str {
        match self {
            Self::Human(_) => "human",
            Self::Agent(_) => "agent",
        }
    }
}
pub(crate) fn project(scope: &Scope) -> StoreResult<se_types::ProjectId> {
    match scope {
        Scope::Project(x) => Ok(x.clone()),
        Scope::Registry => Err(fail(
            StoreErrorCode::ScopeMismatch,
            "project scope required",
        )),
    }
}
pub(crate) fn canonical(wire: &str) -> Option<Vec<u8>> {
    let (prefix, suffix) = wire.split_once('_')?;
    if !matches!(
        prefix,
        "prj" | "ag" | "hu" | "ses" | "msg" | "dec" | "ev" | "lch" | "obs" | "store" | "life"
    ) {
        return None;
    }
    let id = Uuid::parse_str(suffix).ok()?;
    (id.get_version() == Some(Version::SortRand) && id.get_variant() == Variant::RFC4122)
        .then(|| id.as_bytes().to_vec())
}
pub(crate) fn key(
    db: &Connection,
    kind: &str,
    wire: &str,
    scope: &[u8],
    insert: bool,
) -> StoreResult<Vec<u8>> {
    if let Some(bytes) = canonical(wire) {
        return Ok(bytes);
    }
    let old: Option<Vec<u8>> = db
        .query_row(
            "SELECT storage_key FROM identities WHERE kind=? AND scope_key=? AND wire_id=?",
            crate::sql_value::sql_params![kind, scope, wire],
            |r| crate::sql_value::value(r, 0),
        )
        .optional()
        .map_err(sql)?;
    if let Some(bytes) = old {
        return Ok(bytes);
    }
    let mut hash = Sha256::new();
    hash.update(kind);
    hash.update([0]);
    hash.update(scope);
    hash.update([0]);
    hash.update(wire);
    let mut bytes = hash.finalize()[..16].to_vec();
    bytes[6] = (bytes[6] & 15) | 0x80;
    bytes[8] = (bytes[8] & 63) | 0x80;
    if insert {
        db.execute("INSERT INTO identities(storage_key,kind,wire_id,scope_key,encoding) VALUES(?,?,?,?,'legacy-shape')",crate::sql_value::sql_params![bytes,kind,wire,scope]).map_err(sql)?;
    }
    Ok(bytes)
}
pub(crate) fn scope_key(db: &Connection, scope: &Scope, insert: bool) -> StoreResult<Vec<u8>> {
    match scope {
        Scope::Registry => Ok(vec![0]),
        Scope::Project(p) => {
            let mut v = vec![1];
            v.extend(key(db, "project", p.as_str(), &[0], insert)?);
            Ok(v)
        }
    }
}
pub(crate) fn wire(db: &Connection, kind: &str, bytes: &[u8], scope: &[u8]) -> StoreResult<String> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| invalid("invalid stored UUID length"))?;
    let id = Uuid::from_bytes(bytes);
    if id.get_version() == Some(Version::SortRand) && id.get_variant() == Variant::RFC4122 {
        let prefix = match kind {
            "project" => "prj_",
            "agent" => "ag_",
            "human" => "hu_",
            "session" => "ses_",
            "message" => "msg_",
            "decision" => "dec_",
            "event" => "ev_",
            "store" => "store_",
            "lifecycle" => "life_",
            _ => return Err(invalid("unknown identity kind")),
        };
        return Ok(format!("{prefix}{id}"));
    }
    db.query_row(
        "SELECT wire_id FROM identities WHERE storage_key=? AND kind=? AND scope_key=?",
        crate::sql_value::sql_params![bytes.as_slice(), kind, scope],
        |r| crate::sql_value::value(r, 0),
    )
    .map_err(sql)
}
pub(crate) fn actor(db: &Connection, bytes: &[u8], scope: &[u8]) -> StoreResult<Actor> {
    if scope.len() == 17 && scope[0] == 1 {
        let kind: Option<String> = db
            .prepare_cached(
                "SELECT principal_kind FROM principals WHERE project_id=? AND principal_id=?",
            )
            .map_err(sql)?
            .query_row(crate::sql_value::sql_params![&scope[1..], bytes], |r| {
                crate::sql_value::value(r, 0)
            })
            .optional()
            .map_err(sql)?;
        if kind.as_deref() == Some("agent") {
            return Ok(Actor::Agent(
                wire(db, "agent", bytes, scope)?.parse().map_err(invalid)?,
            ));
        }
    }
    let owner: bool = db
        .prepare_cached("SELECT EXISTS(SELECT 1 FROM owners WHERE human_id=?)")
        .map_err(sql)?
        .query_row([bytes], |r| crate::sql_value::value(r, 0))
        .map_err(sql)?;
    if owner {
        return Ok(Actor::Human(
            wire(db, "human", bytes, &[0])?.parse().map_err(invalid)?,
        ));
    }
    Ok(Actor::Agent(
        wire(db, "agent", bytes, scope)?.parse().map_err(invalid)?,
    ))
}
