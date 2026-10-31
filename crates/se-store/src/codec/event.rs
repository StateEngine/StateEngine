use crate::{connection, error::*, identity::*, *};
use rusqlite::{Connection, OptionalExtension, params};
use se_types::{ProjectId, StoreId};

pub(crate) fn load_event(c: &Connection, seq: i64, info: &StoreInfo) -> StoreResult<StoredEvent> {
    let (id,p,actor_id,session,origin,door,kind,version,inc,rev,mode,generation,durability,occurred,recorded,cause,supersedes):(Vec<u8>,Option<Vec<u8>>,Vec<u8>,Option<Vec<u8>>,Vec<u8>,String,String,u32,u64,u64,String,Option<u64>,String,i64,i64,Option<Vec<u8>>,Option<Vec<u8>>)=c.query_row("SELECT event_id,project_id,actor_id,session_id,origin_id,door,kind,schema_version,recorded_incarnation,entity_revision,writer_mode,host_generation,durability,occurred_at_us,recorded_at_us,cause_event_id,supersedes_event_id FROM events WHERE seq=?",[seq],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?,r.get(10)?,r.get(11)?,r.get(12)?,r.get(13)?,r.get(14)?,r.get(15)?,r.get(16)?))).map_err(sql)?;
    if version != 1 {
        return Err(fail(
            StoreErrorCode::Unreadable,
            "unknown event schema version",
        ));
    }
    let scope = match p {
        Some(p) => Scope::Project(wire(c, "project", &p, &[0])?.parse().map_err(invalid)?),
        None => Scope::Registry,
    };
    let s = scope_key(c, &scope, false)?;
    let parse_event = |k: &[u8]| wire(c, "event", k, &s).and_then(|v| v.parse().map_err(invalid));
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
                .map(|v| wire(c, "session", &v, &s).and_then(|v| v.parse().map_err(invalid)))
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
        body: super::body(c, seq, &kind, &scope)?,
        erased_fields: Vec::new(),
    })
}
