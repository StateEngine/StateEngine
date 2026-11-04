//! Transaction-only projections. No native, network or provider calls.
pub(crate) mod capture;
pub(crate) mod credential;
pub(crate) mod cursor;
pub(crate) mod decision;
pub(crate) mod effect;
mod mail;
mod message;
mod revision;
mod work_message;
pub(crate) use revision::{expected, revision_for};
mod principal;
pub(crate) mod process;
pub(crate) mod project;
pub(crate) mod session;
use crate::{codec, connection::*, error::*, identity::*, *};
use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;
pub(crate) fn natural(c: &Connection, e: &NewEvent) -> StoreResult<Option<i64>> {
    let scope = scope_key(c, &e.header.scope, false)?;
    let event = key(c, "event", e.header.event.as_str(), &scope, false)?;
    let existing = c
        .query_row("SELECT seq FROM events WHERE event_id=?", [event], |r| {
            crate::sql_value::value(r, 0)
        })
        .optional()
        .map_err(sql)?;
    if existing.is_some() {
        return Ok(existing);
    }
    if let EventBody::MessageSent { message, .. } | EventBody::WorkMessageSent { message, .. } =
        &e.body
    {
        let p = project_id(c, &e.header.scope, false)?;
        let m = key(c, "message", message.as_str(), &scope, false)?;
        return c
            .query_row(
                &format!(
                    "SELECT sent_seq FROM {} WHERE project_id=? AND message_id=? LIMIT 1",
                    connection::mail_table(c)?
                ),
                crate::sql_value::sql_params![p, m],
                |r| crate::sql_value::value(r, 0),
            )
            .optional()
            .map_err(sql);
    }
    if matches!(
        e.body,
        EventBody::SessionTurn { .. }
            | EventBody::CaptureSource { .. }
            | EventBody::CaptureProgress { .. }
    ) {
        return codec::capture::natural(c, e);
    }
    let (message, recipient, col) = match &e.body {
        EventBody::MessageRead { message, recipient } => (message, recipient, "read_seq"),
        EventBody::MessageDismissed { message, recipient } => (message, recipient, "dismissed_seq"),
        EventBody::MessageDelivered {
            message, recipient, ..
        } => (message, recipient, "delivered_seq"),
        _ => return Ok(None),
    };
    let project = project_id(c, &e.header.scope, false)?;
    let message = key(c, "message", message.as_str(), &scope, false)?;
    let recipient = key(
        c,
        recipient.kind(),
        recipient.wire(),
        if recipient.kind() == "human" {
            &[0]
        } else {
            &scope
        },
        false,
    )?;
    let statement = if connection::mail_table(c)? == "message_deliveries" {
        format!(
            "SELECT {col} FROM message_deliveries WHERE project_id=? AND message_id=? AND recipient_id=?"
        )
    } else {
        format!(
            "SELECT m.{col} FROM marks m JOIN messages d ON d.sent_seq=m.message_seq WHERE d.project_id=? AND d.message_id=? AND m.recipient_id=?"
        )
    };
    c.query_row(
        &statement,
        crate::sql_value::sql_params![project, message, recipient],
        |r| crate::sql_value::value(r, 0),
    )
    .optional()
    .map_err(sql)
    .map(Option::flatten)
}
pub(crate) fn apply(
    c: &Connection,
    header: &EventHeader,
    body: EventBody<InputText>,
    seq: i64,
    revision: u64,
    facts: Value,
    lease: &LeaseIdentity,
) -> StoreResult<()> {
    use EventBody::*;
    let s = scope_key(c, &header.scope, true)?;
    let pk = match &header.scope {
        Scope::Registry => None,
        Scope::Project(_) => Some(project_id(c, &header.scope, true)?),
    };
    if let Some(p) = &pk {
        let removed_at: Option<i64> = c
            .query_row(
                "SELECT e.recorded_at_us FROM projects p JOIN events e ON e.seq=p.last_seq WHERE p.project_id=? AND p.state='removed'",
                [p],
                |r| r.get(0),
            )
            .optional()
            .map_err(sql)?;
        if let (Some(at), Scope::Project(project)) = (removed_at, &header.scope)
            && header.door != Door::Import
        {
            let mut e = fail(
                StoreErrorCode::ProjectRemoved,
                format!("project {project} was removed; its history is retained"),
            );
            e.detail = StoreDetail::ProjectRemoved {
                project: project.clone(),
                at: se_types::UnixMicros::new(u64::try_from(at).map_err(invalid)?)
                    .map_err(invalid)?,
            };
            return Err(e);
        }
    }
    let project = || {
        pk.as_ref().ok_or_else(|| {
            fail(
                StoreErrorCode::ScopeMismatch,
                "project event in registry scope",
            )
        })
    };
    let actor_key = |a: &Actor| {
        key(
            c,
            a.kind(),
            a.wire(),
            if a.kind() == "human" { &[0] } else { &s },
            true,
        )
    };
    match body {
        b @ (ProcessRegistered { .. } | ProcessTransition { .. }) => {
            process::apply(c, header, b, seq, revision, lease)?
        }
        ProjectRegistered {
            project: p,
            roots,
            owner,
            ..
        } => {
            if header.actor != Actor::Human(owner.clone()) {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "project registration actor must be its admitted owner",
                ));
            }
            let p = key(c, "project", p.as_str(), &[0], true)?;
            if pk.as_ref().is_some_and(|scope| *scope != p) {
                return Err(fail(
                    StoreErrorCode::ScopeMismatch,
                    "project identity differs from event scope",
                ));
            }
            let own = key(c, "human", owner.as_str(), &[0], true)?;
            let exists: bool = c
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM owners WHERE human_id=?)",
                    [own],
                    |r| crate::sql_value::value(r, 0),
                )
                .map_err(sql)?;
            if !exists {
                return Err(fail(
                    StoreErrorCode::ReferenceMissing,
                    "register the owner before the project",
                ));
            }
            c.execute("INSERT INTO projects(project_id,first_seq,revision,last_seq,state) VALUES(?,?,?,?,'active')",crate::sql_value::sql_params![p,seq,revision,seq]).map_err(sql)?;
            for root in roots {
                let encoded = symbol(c, codec::encode(&root.path)?.as_bytes())?;
                c.execute("INSERT INTO roots(project_id,canonical_key,encoded_path,last_seq) VALUES(?,?,?,?)",crate::sql_value::sql_params![p,root.canonical_key,encoded,seq]).map_err(sql)?;
            }
            codec::aux(c, seq, facts)?;
        }
        PrincipalRegistered {
            principal,
            kind,
            owner,
            created_by,
            name,
            ..
        } => {
            if name.is_empty() || name.len() > 64 {
                return Err(invalid("principal name bounds"));
            }
            if matches!(principal, Actor::Agent(_))
                && (!name.as_bytes()[0].is_ascii_alphanumeric()
                    || !name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b" ._-".contains(&b)))
            {
                return Err(invalid("agent name grammar"));
            }
            if matches!(kind, PrincipalKind::Agent) != matches!(principal, Actor::Agent(_)) {
                return Err(invalid("principal kind differs from ID"));
            }
            principal::name_available(c, &header.scope, &principal, &name)?;
            let a = actor_key(&principal)?;
            if matches!(principal, Actor::Agent(_)) {
                let collision: bool = c
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM owners WHERE human_id=?)",
                        [&a],
                        |r| crate::sql_value::value(r, 0),
                    )
                    .map_err(sql)?;
                if collision {
                    return Err(fail(
                        StoreErrorCode::EventIdConflict,
                        "agent identity bytes collide with an existing human; allocate a fresh agent ID",
                    ));
                }
            }

            let own = key(c, "human", owner.as_str(), &[0], true)?;
            if pk.is_none() {
                if principal != Actor::Human(owner)
                    || header.actor != principal
                    || created_by.is_some()
                {
                    return Err(invalid(
                        "registry owner bootstrap requires self owner, no invented creator",
                    ));
                }
                c.execute("INSERT INTO owners(human_id,display_name,first_seq,revision,last_seq) VALUES(?,?,?,?,?)",crate::sql_value::sql_params![a,name,seq,revision,seq]).map_err(sql)?;
            } else {
                if header.door != Door::Import
                    && header.actor != Actor::Human(owner.clone())
                    && created_by.as_ref() != Some(&header.actor)
                {
                    return Err(fail(
                        StoreErrorCode::CreatorControlRefused,
                        "creator differs from admitted actor",
                    ));
                }
                let creator = created_by.as_ref().map(actor_key).transpose()?;
                c.execute("INSERT INTO principals(project_id,principal_id,principal_kind,owner_id,created_by,display_name,first_seq,revision,last_seq)
                    VALUES(?,?,?,?,?,?,?,?,?)",crate::sql_value::sql_params![project()?,a,if matches!(kind,PrincipalKind::Agent){"agent"}else{"human"},own,creator,name,seq,revision,seq]).map_err(sql)?;
                c.execute("INSERT INTO resume_heads(project_id,principal_id,unread_count,pending_effect_count,last_seq) VALUES(?,?,0,0,?)",crate::sql_value::sql_params![project()?,a,seq]).map_err(sql)?;
            }
            codec::aux(c, seq, facts)?;
        }
        PrincipalRenamed {
            principal, name, ..
        } => {
            principal::name_available(c, &header.scope, &principal, &name)?;
            let a = actor_key(&principal)?;
            c.execute("UPDATE principals SET display_name=?,revision=?,last_seq=? WHERE project_id=? AND principal_id=?",crate::sql_value::sql_params![name,revision,seq,project()?,a]).map_err(sql)?;
            codec::aux(c, seq, facts)?;
        }
        ProfileSaved { agent, profile, .. } => {
            if matches!(profile.permission, PermissionProfile::NamedFullBypass)
                && profile.named_profile.is_empty()
            {
                return Err(invalid("bypass needs an explicit named profile"));
            }
            let a = key(c, "agent", agent.as_str(), &s, true)?;
            c.execute("INSERT INTO profiles(project_id,agent_id,revision,last_seq) VALUES(?,?,?,?) ON CONFLICT(project_id,agent_id)
                    DO UPDATE SET revision=excluded.revision,last_seq=excluded.last_seq WHERE profiles.revision=excluded.revision-1",crate::sql_value::sql_params![project()?,a,revision,seq]).map_err(sql)?;
            codec::aux(c, seq, facts)?;
        }
        GrantRecorded {
            principal,
            key: grant,
            active,
            ..
        } => {
            if !matches!(header.actor, Actor::Human(_)) {
                return Err(fail(
                    StoreErrorCode::CreatorControlRefused,
                    "only owner may change grants",
                ));
            }
            c.execute("INSERT INTO grants(scope_key,principal_id,grant_key,revision,last_seq,active) VALUES(?,?,?,?,?,?)
                    ON CONFLICT(scope_key,principal_id,grant_key) DO UPDATE SET revision=excluded.revision,last_seq=excluded.last_seq,active=excluded.active
                    WHERE grants.revision=excluded.revision-1",crate::sql_value::sql_params![s,actor_key(&principal)?,codec::encode(&grant)?,revision,seq,active]).map_err(sql)?;
            codec::aux(c, seq, facts)?;
        }
        MessageSent {
            message,
            recipient,
            kind,
            body,
            refs,
            reply_to,
        } => {
            if refs.len() > 64
                || !matches!(
                    kind.as_str(),
                    "note"
                        | "task"
                        | "question"
                        | "answer"
                        | "blocker"
                        | "done"
                        | "handoff"
                        | "finding"
                )
            {
                return Err(invalid("message refs/kind bounds"));
            }
            let m = key(c, "message", message.as_str(), &s, true)?;
            let recipient = actor_key(&recipient)?;
            let sender = actor_key(&header.actor)?;
            let exists: bool = c
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM principals WHERE project_id=? AND principal_id=?)",
                    crate::sql_value::sql_params![project()?, recipient],
                    |r| crate::sql_value::value(r, 0),
                )
                .map_err(sql)?;
            if !exists {
                return Err(fail(
                    StoreErrorCode::ReferenceMissing,
                    "message recipient is not registered in this project",
                ));
            }
            let body = payload(
                c,
                seq,
                "body",
                &codec::text(body, se_types::MESSAGE_BODY_MAX_BYTES)?,
            )?;
            let reply = reply_to
                .map(|id| key(c, "message", id.as_str(), &s, false))
                .transpose()?;
            for r in &refs {
                let k = key(c, "event", r.as_str(), &s, false)?;
                let ok: bool = c
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM events WHERE project_id=? AND event_id=?)",
                        crate::sql_value::sql_params![project()?, k],
                        |r| crate::sql_value::value(r, 0),
                    )
                    .map_err(sql)?;
                if !ok {
                    return Err(fail(
                        StoreErrorCode::ReferenceMissing,
                        "message ref outside scope or absent",
                    ));
                }
            }
            c.execute("INSERT INTO message_data(event_seq,message_id,recipient_id,message_kind,body_payload,refs,reply_to)
                    VALUES(?,?,?,?,?,?,?)",crate::sql_value::sql_params![seq,m,recipient,kind,body,codec::encode(&refs)?,reply]).map_err(sql)?;
            c.execute("INSERT INTO messages(project_id,message_id,sent_seq,sender_id,recipient_id,message_kind,revision)
                    VALUES(?,?,?,?,?,?,?)",crate::sql_value::sql_params![project()?,m,seq,sender,recipient,kind,revision]).map_err(sql)?;
            c.execute(
                "INSERT INTO marks(message_seq,project_id,recipient_id) VALUES(?,?,?)",
                crate::sql_value::sql_params![seq, project()?, recipient],
            )
            .map_err(sql)?;
            if connection::mail_table(c)? == "message_deliveries" {
                c.execute("INSERT INTO message_deliveries(project_id,message_id,sent_seq,sender_id,recipient_id,message_kind,is_floor,revision) VALUES(?,?,?,?,?,?,0,?)",crate::sql_value::sql_params![project()?,m,seq,sender,recipient,kind,revision]).map_err(sql)?;
            }
            count(c, project()?, &recipient, 1, seq)?;
        }
        body @ MessageSuperseded { .. } => {
            message::supersede(c, header, body, seq, revision, facts)?
        }
        body @ WorkMessageSent { .. } => work_message::send(c, header, body, seq, revision, facts)?,
        body @ (MessageRead { .. } | MessageDismissed { .. } | MessageDelivered { .. }) => {
            work_message::mark(c, header, body, seq, revision)?;
        }
        WorkingStateSet {
            agent,
            text,
            expected: want,
        } => {
            let a = key(c, "agent", agent.as_str(), &s, true)?;
            let p = payload(
                c,
                seq,
                "body",
                &codec::text(text, se_types::WORKING_STATE_MAX_BYTES)?,
            )?;
            let want = match want {
                Expected::Absent => None,
                Expected::Revision(r) => Some(r.value.get()),
            };
            c.execute("INSERT INTO working_state_data(event_seq,agent_id,text_payload,expected_revision) VALUES(?,?,?,?)",crate::sql_value::sql_params![seq,a,p,want]).map_err(sql)?;
            c.execute("INSERT INTO working_state(project_id,agent_id,revision,last_seq) VALUES(?,?,?,?) ON CONFLICT(project_id,agent_id)
                    DO UPDATE SET revision=excluded.revision,last_seq=excluded.last_seq WHERE working_state.revision=excluded.revision-1",crate::sql_value::sql_params![project()?,a,revision,seq]).map_err(sql)?;
            let changed=c.execute("UPDATE resume_heads SET last_working_state_seq=?,last_seq=? WHERE project_id=? AND principal_id=?",crate::sql_value::sql_params![seq,seq,project()?,a]).map_err(sql)?;
            if changed != 1 {
                return Err(fail(
                    StoreErrorCode::ProjectionInconsistent,
                    "working-state resume head absent",
                ));
            }
        }
        RuntimeOwnerEstablished {
            epoch,
            generation,
            expected_owner_generation,
            ..
        } => {
            if pk.is_some() || lease.mode != LeaseMode::Host || lease.generation != generation.get()
            {
                return Err(fail(
                    StoreErrorCode::GenerationChanged,
                    "runtime owner requires matching exclusive host generation",
                ));
            }
            let old: Option<u64> = c
                .query_row(
                    "SELECT owner_generation FROM runtime_owner WHERE singleton=1",
                    [],
                    |r| crate::sql_value::value(r, 0),
                )
                .optional()
                .map_err(sql)?;
            if old != expected_owner_generation.map(|g| g.get())
                || old.is_some_and(|g| g >= generation.get())
            {
                return Err(fail(
                    StoreErrorCode::GenerationChanged,
                    "owner predecessor generation differs",
                ));
            }
            c.execute("INSERT INTO runtime_owner(singleton,owner_generation,owner_epoch,revision,last_seq) VALUES(1,?,?,?,?)
                    ON CONFLICT(singleton) DO UPDATE SET owner_generation=excluded.owner_generation,owner_epoch=excluded.owner_epoch,revision=excluded.revision,last_seq=excluded.last_seq",crate::sql_value::sql_params![generation.get(),codec::encode(&epoch)?,revision,seq]).map_err(sql)?;
            codec::aux(c, seq, facts)?;
        }
        b @ (DecisionProposed { .. }
        | DecisionRatified { .. }
        | DecisionRejected { .. }
        | DecisionRetracted { .. }
        | DecisionSuperseded { .. }) => decision::apply(c, header, b, seq, revision)?,
        b @ (SessionPrepared { .. }
        | SessionActivated { .. }
        | SessionEnded { .. }
        | SessionRevoked { .. }) => session::apply(c, header, b, seq, revision, lease)?,
        b @ (SessionTurn { .. }
        | CaptureSource { .. }
        | CaptureProgress { .. }
        | CaptureFailed { .. }
        | CaptureSuppressed { .. }) => capture::apply(c, header, b, seq, revision, facts)?,
        b @ (CredentialIssued { .. } | CredentialActivated { .. } | CredentialRevoked { .. }) => {
            credential::apply(c, header, b, seq, revision, facts)?
        }
        b @ (EffectRequested { .. }
        | EffectOffered { .. }
        | EffectSettled { .. }
        | IntegrationRecorded { .. }) => effect::apply(c, header, b, seq, revision, facts, lease)?,
        b @ ProjectUpdated { .. } => project::update(c, header, b, seq, revision, facts)?,
        b @ ProjectRemoved { .. } => project::apply(c, header, b, seq, revision, facts)?,
        b @ (CursorRecorded { .. } | CursorAcknowledged { .. }) => {
            cursor::apply(c, header, b, seq, revision, facts)?
        }
        b @ (ImportStarted { .. }
        | ImportProgress { .. }
        | ImportFinished { .. }
        | ImportUnreadable { .. }
        | LegacyRetained { .. }
        | AliasImported { .. }) => crate::import::apply(c, header, b, seq, revision, facts)?,
        _ => return later("projection"),
    }
    Ok(())
}
fn count(c: &Connection, p: &[u8], a: &[u8], delta: i64, seq: i64) -> StoreResult<()> {
    let changed=c.execute("UPDATE resume_heads SET unread_count=unread_count+?,last_seq=? WHERE project_id=? AND principal_id=?",crate::sql_value::sql_params![delta,seq,p,a]).map_err(sql)?;
    if changed != 1 {
        return Err(fail(
            StoreErrorCode::ProjectionInconsistent,
            "recipient resume head absent",
        ));
    }
    Ok(())
}
