type EnvelopeRow = (
    Vec<u8>,
    Option<Vec<u8>>,
    Vec<u8>,
    Option<Vec<u8>>,
    Vec<u8>,
    String,
    String,
    u32,
    u64,
    u64,
    String,
    Option<u64>,
    String,
    i64,
    i64,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);
use crate::{error::*, identity::*, *};
use rusqlite::Connection;
use se_types::StoreId;

pub(crate) fn load_event(c: &Connection, seq: i64, info: &StoreInfo) -> StoreResult<StoredEvent> {
    let (id,p,actor_id,session,origin,door,kind,version,inc,rev,mode,generation,durability,occurred,recorded,cause,supersedes):EnvelopeRow=c.prepare_cached("SELECT event_id,project_id,actor_id,session_id,origin_id,door,kind,schema_version,recorded_incarnation,entity_revision,writer_mode,host_generation,durability,occurred_at_us,recorded_at_us,cause_event_id,supersedes_event_id FROM events WHERE seq=?").map_err(sql)?.query_row([seq],|r|Ok((crate::sql_value::value(r,0)?,crate::sql_value::value(r,1)?,crate::sql_value::value(r,2)?,crate::sql_value::value(r,3)?,crate::sql_value::value(r,4)?,crate::sql_value::value(r,5)?,crate::sql_value::value(r,6)?,crate::sql_value::value(r,7)?,crate::sql_value::value(r,8)?,crate::sql_value::value(r,9)?,crate::sql_value::value(r,10)?,crate::sql_value::value(r,11)?,crate::sql_value::value(r,12)?,crate::sql_value::value(r,13)?,crate::sql_value::value(r,14)?,crate::sql_value::value(r,15)?,crate::sql_value::value(r,16)?))).map_err(sql)?;
    if version != 1 && !(version == 2 && kind == "profile.saved") {
        return Err(fail(
            StoreErrorCode::VersionUnsupported,
            "unknown event schema version",
        ));
    }
    let scope = match p {
        Some(p) => Scope::Project(project_from_key(c, &p)?),
        None => Scope::Registry,
    };
    let s = scope_key(c, &scope, false)?;
    let parse_event =
        |k: &[u8]| wire(c, "event", k, &s).and_then(|v| v.try_into().map_err(invalid));
    let body = super::body(c, seq, &kind, &scope)?;
    if version == 2
        && !matches!(&body, EventBody::ProfileSaved { profile, .. } if profile.harness.is_some())
    {
        return Err(invalid(
            "descriptor-bound profile is missing its harness selection",
        ));
    }
    let writer = match (mode.as_str(), generation) {
        ("direct", None) => LeaseIdentity {
            store: Some(info.id.clone()),
            generation: 1,
            mode: LeaseMode::DirectClient,
        },
        ("host", Some(g)) if g > 0 => LeaseIdentity {
            store: Some(info.id.clone()),
            generation: g,
            mode: LeaseMode::Host,
        },
        _ => return Err(invalid("invalid persisted writer stamp")),
    };
    Ok(StoredEvent {
        header: EventHeader {
            event: parse_event(&id)?,
            scope: scope.clone(),
            actor: actor(c, &actor_id, &s)?,
            session: session
                .map(|v| wire(c, "session", &v, &s).and_then(|v| v.try_into().map_err(invalid)))
                .transpose()?,
            origin: StoreId::from_bytes(
                origin.try_into().map_err(|_| invalid("origin ID length"))?,
            )
            .map_err(invalid)?,
            door: match door.as_str() {
                "cli" => Door::Cli,
                "mcp" => Door::Mcp,
                "hook" => Door::Hook,
                "host" => Door::Host,
                "import" => Door::Import,
                _ => return Err(invalid("invalid stored door")),
            },
            occurred_at_us: occurred,
            cause: cause.map(|v| parse_event(&v)).transpose()?,
            supersedes: supersedes.map(|v| parse_event(&v)).transpose()?,
        },
        revision: super::revision(rev)?,
        position: StorePosition::new_internal(info.id.clone(), inc, seq as u64)?,
        recorded_at_us: recorded,
        recorded_incarnation: inc,
        writer: WriterMode::from_lease(&writer),
        durability: match durability.as_str() {
            "normal" => CommitDurability::Normal,
            "full" => CommitDurability::Full,
            _ => return Err(invalid("invalid persisted durability")),
        },
        body,
        erased_fields: Vec::new(),
    })
}
