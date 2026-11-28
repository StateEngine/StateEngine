//! Transaction-only projections. No native, network or provider calls.
mod assignment;
pub(crate) mod capture;
pub(crate) mod channel;
pub(crate) use channel::capacity as channel_capacity;
pub(crate) mod credential;
pub(crate) mod cursor;
pub(crate) mod effect;
mod mail;
mod mail_rate;
mod message;
mod notification;
mod revision;
mod work_message;
pub(crate) use revision::{expected, revision_for};
mod principal;
pub(crate) mod process;
pub(crate) mod project;
mod published_turn;
pub(crate) mod session;
use crate::{codec, connection::*, error::*, identity::*, *};
use rusqlite::{Connection, OptionalExtension};
use se_types::ProjectId;
use serde_json::Value;
fn invalid_transition(msg: impl Into<String>) -> Box<StoreError> {
    fail(StoreErrorCode::InvalidTransition, msg)
}
fn scope_mismatch(msg: impl Into<String>) -> Box<StoreError> {
    fail(StoreErrorCode::ScopeMismatch, msg)
}
fn source_changed(msg: impl Into<String>) -> Box<StoreError> {
    fail(StoreErrorCode::SourceChanged, msg)
}
fn reference_missing(msg: impl Into<String>) -> Box<StoreError> {
    fail(StoreErrorCode::ReferenceMissing, msg)
}
fn revision_conflict(msg: impl Into<String>) -> Box<StoreError> {
    fail(StoreErrorCode::RevisionConflict, msg)
}
/// Keep the writer lease and this transaction's closed launch validation together.
pub(crate) struct ApplyAuthority<'a> {
    pub lease: &'a LeaseIdentity,
    pub remote_launch: Option<&'a crate::remote::LaunchAuthority>,
    pub channel_delay_us: i64,
}
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
        if e.header.door != Door::Import
            && !crate::transaction::natural_kind(&e.body)
            && !matches!(
                e.body,
                EventBody::RuntimeOwnerEstablished { .. }
                    | EventBody::RuntimeHandoverRecorded { .. }
            )
        {
            return Err(fail(
                StoreErrorCode::NaturalKeyConflict,
                "event ID already belongs to another operation",
            ));
        }
        return Ok(existing);
    }
    if let EventBody::MessageSent { message, .. } | EventBody::WorkMessageSent { message, .. } =
        &e.body
    {
        let p = project_id(c, &e.header.scope, false)?;
        let m = key(c, "message", message.as_str(), &scope, false)?;
        let prior = c
            .query_row(
                &format!(
                    "SELECT sent_seq FROM {} WHERE project_id=? AND message_id=? LIMIT 1",
                    connection::mail_table(c)?
                ),
                crate::sql_value::sql_params![p, m],
                |r| crate::sql_value::value(r, 0),
            )
            .optional()
            .map_err(sql)?;
        if prior.is_some() && e.header.door != Door::Import {
            return Err(fail(
                StoreErrorCode::NaturalKeyConflict,
                "message ID already belongs to another operation",
            ));
        }
        return Ok(prior);
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
    let recipient = actor_key(c, recipient, &scope, false)?;
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
/// What the inline projections share: the transaction, the admitted header,
/// its scope keys and the sequence and revision this event writes.
#[derive(Clone, Copy)]
struct Ctx<'a> {
    c: &'a Connection,
    header: &'a EventHeader,
    s: &'a [u8],
    pk: Option<&'a [u8]>,
    seq: i64,
    revision: u64,
}
impl<'a> Ctx<'a> {
    fn project(&self) -> StoreResult<&'a [u8]> {
        self.pk.ok_or_else(|| {
            fail(
                StoreErrorCode::ScopeMismatch,
                "project event in registry scope",
            )
        })
    }
    fn actor(&self, a: &Actor) -> StoreResult<Vec<u8>> {
        actor_key(self.c, a, self.s, true)
    }
}
/// A principal's key in its identity scope; humans are registry-wide.
fn actor_key(c: &Connection, a: &Actor, scope: &[u8], create: bool) -> StoreResult<Vec<u8>> {
    key(
        c,
        a.kind(),
        a.wire(),
        if a.kind() == "human" { &[0] } else { scope },
        create,
    )
}
pub(crate) fn apply(
    c: &Connection,
    header: &EventHeader,
    body: EventBody<InputText>,
    seq: i64,
    revision: u64,
    facts: Value,
    authority: &ApplyAuthority<'_>,
) -> StoreResult<()> {
    use EventBody::*;
    let s = scope_key(c, &header.scope, true)?;
    let pk = match &header.scope {
        Scope::Registry => None,
        Scope::Project(_) => Some(project_id(c, &header.scope, true)?),
    };
    if let Some(p) = &pk {
        refuse_removed(c, header, p)?;
    }
    let x = Ctx {
        c,
        header,
        s: &s,
        pk: pk.as_deref(),
        seq,
        revision,
    };
    match body {
        ChannelRecorded { change } => channel::apply(
            c,
            header,
            change,
            seq,
            revision,
            facts,
            authority.channel_delay_us,
        )?,
        b @ (ProcessRegistered { .. } | ProcessTransition { .. }) => {
            process::apply(c, header, b, seq, revision, authority)?
        }
        b @ (AssignmentOpened { .. } | AssignmentTransitioned { .. }) => {
            assignment::apply(c, header, b, seq, revision, facts)?
        }
        b @ MessageSent { .. } => send_message(x, b)?,
        body @ MessageSuperseded { .. } => {
            message::supersede(c, header, body, seq, revision, facts)?
        }
        body @ WorkMessageSent { .. } => work_message::send(c, header, body, seq, revision, facts)?,
        body @ (MessageRead { .. } | MessageDismissed { .. } | MessageDelivered { .. }) => {
            work_message::mark(c, header, body, seq, revision)?
        }
        b @ WorkingStateSet { .. } => set_working_state(x, b)?,
        SessionTurnPublished { turn, body } => published_turn::apply(c, header, seq, turn, body)?,
        b @ (SessionPrepared { .. }
        | SessionActivated { .. }
        | SessionEnded { .. }
        | SessionRevoked { .. }) => session::apply(c, header, b, seq, revision, authority)?,
        b @ (SessionTurn { .. }
        | CaptureSource { .. }
        | CaptureProgress { .. }
        | CaptureFailed { .. }
        | CaptureVerified { .. }
        | CaptureSuppressed { .. }) => capture::apply(c, header, b, seq, revision, facts)?,
        b @ (CredentialIssued { .. }
        | CredentialActivated { .. }
        | CredentialRevoked { .. }
        | CredentialRotated { .. }) => credential::apply(c, header, b, seq, revision, facts)?,
        b @ (EffectRequested { .. }
        | EffectOffered { .. }
        | EffectSettled { .. }
        | IntegrationRecorded { .. }) => {
            effect::apply(c, header, b, seq, revision, facts, authority.lease)?
        }
        b @ ProjectUpdated { .. } => project::update(c, header, b, seq, revision, facts)?,
        b @ ProjectMoved { .. } => project::move_root(c, header, b, seq, revision, facts)?,
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
        body => {
            recorded(x, body, authority)?;
            codec::aux(c, seq, facts)?;
        }
    }
    Ok(())
}
/// A removed project keeps its history; only imports may still write to it.
fn refuse_removed(c: &Connection, header: &EventHeader, p: &[u8]) -> StoreResult<()> {
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
            at: se_types::UnixMicros::new(u64::try_from(at).map_err(invalid)?).map_err(invalid)?,
        };
        return Err(e);
    }
    Ok(())
}
/// Projections whose event facts are kept as auxiliary data once they apply.
fn recorded(
    x: Ctx<'_>,
    body: EventBody<InputText>,
    authority: &ApplyAuthority<'_>,
) -> StoreResult<()> {
    use EventBody::*;
    let (c, header, s, seq, revision) = (x.c, x.header, x.s, x.seq, x.revision);
    match body {
        RemoteSecurity { transition } => {
            crate::remote::apply(c, header, transition, seq, revision)?
        }
        RemoteMessageAttributed { record } => {
            crate::remote::remember_source(c, &record, seq)?;
            let p = project_id(c, &header.scope, false)?;
            let message = key(c, "message", record.message.as_str(), s, false)?;
            let grant = key(c, "remote-grant", record.grant.as_str(), &[0], false)?;
            c.execute("INSERT INTO remote_message_attribution(event_seq,project_id,message_id,grant_id,facts) VALUES(?,?,?,?,?)",rusqlite::params![seq,p,message,grant,codec::encode(&record)?]).map_err(sql)?;
        }
        RemoteLaunchAttributed { record } => crate::remote::apply_launch(c, header, record, seq)?,
        RemoteDelegateAttributed { record } => crate::remote::apply_delegate(c, header, &record)?,
        RemoteMailboxRecorded { change } => crate::remote::apply_mailbox(c, header, change, seq)?,
        CaptainMessageRouted { captain, .. } => assignment::check_route(c, header, &captain)?,
        ProjectCaptainChanged {
            project: target,
            captain,
            ..
        } => change_captain(x, &target, captain)?,
        b @ ProjectRegistered { .. } => register_project(x, b)?,
        b @ PrincipalRegistered { .. } => principal::register(&x, b, authority)?,
        PrincipalRenamed {
            principal, name, ..
        } => {
            principal::name_available(c, &header.scope, &principal, &name)?;
            let a = x.actor(&principal)?;
            c.execute("UPDATE principals SET display_name=?,revision=?,last_seq=? WHERE project_id=? AND principal_id=?",crate::sql_value::sql_params![name,revision,seq,x.project()?,a]).map_err(sql)?;
        }
        AgentRetired {
            agent,
            final_session,
            ..
        } => principal::retire(
            c,
            header,
            s,
            x.project()?,
            &agent,
            final_session.as_ref(),
            seq,
        )?,
        ProfileSaved { agent, profile, .. } => save_profile(&x, &agent, &profile)?,
        GrantRecorded {
            principal,
            key: grant,
            active,
            ..
        } => record_grant(&x, &principal, &grant, active)?,
        b @ RuntimeOwnerEstablished { .. } => runtime_owner(x, b, authority.lease)?,
        DecisionProposed { .. }
        | DecisionRatified { .. }
        | DecisionRejected { .. }
        | DecisionRetracted { .. }
        | DecisionSuperseded { .. } => {
            return Err(fail(
                StoreErrorCode::VersionUnsupported,
                "decision ledger writes are retired; existing events remain readable through history",
            ));
        }
        ErasureRequested {
            erasure,
            targets,
            residuals,
            generations,
        } => crate::erasure::apply::requested(
            c,
            seq,
            &erasure,
            &targets,
            &residuals,
            generations.as_deref(),
        )?,
        TurnErased {
            target,
            erasure,
            original_bytes,
            ..
        } => crate::erasure::apply::body(c, s, &target, &erasure, original_bytes, "turn")?,
        MessageErased {
            target,
            erasure,
            original_bytes,
            ..
        } => crate::erasure::apply::body(c, s, &target, &erasure, original_bytes, "message")?,
        RecoveryRecorded { receipt, .. } => {
            let text = receipt.as_materialized()?;
            if text.len() > 1024 * 1024 {
                return Err(invalid("restore receipt exceeds 1 MiB"));
            }
            payload(c, seq, "restore-receipt", text)?;
        }
        ErasureCompleted { erasure, .. } => crate::erasure::apply::completed(c, seq, &erasure)?,
        _ => return later("projection"),
    }
    Ok(())
}
fn save_profile(x: &Ctx<'_>, agent: &se_types::AgentId, profile: &Profile) -> StoreResult<()> {
    profile
        .provider_settings
        .validate(profile.provider.into())
        .map_err(|_| invalid("invalid saved provider settings"))?;
    if matches!(profile.permission, PermissionProfile::NamedFullBypass)
        && profile.named_profile.is_empty()
    {
        return Err(invalid("bypass needs an explicit named profile"));
    }
    let a = key(x.c, "agent", agent.as_str(), x.s, true)?;
    x.c.execute(
        "INSERT INTO profiles(project_id,agent_id,revision,last_seq) VALUES(?,?,?,?) ON CONFLICT(project_id,agent_id)
                DO UPDATE SET revision=excluded.revision,last_seq=excluded.last_seq WHERE profiles.revision=excluded.revision-1",
        crate::sql_value::sql_params![x.project()?, a, x.revision, x.seq],
    )
    .map_err(sql)?;
    Ok(())
}
fn record_grant(x: &Ctx<'_>, principal: &Actor, grant: &GrantKey, active: bool) -> StoreResult<()> {
    if !matches!(x.header.actor, Actor::Human(_)) {
        return Err(fail(
            StoreErrorCode::CreatorControlRefused,
            "only owner may change grants",
        ));
    }
    x.c.execute(
        "INSERT INTO grants(scope_key,principal_id,grant_key,revision,last_seq,active) VALUES(?,?,?,?,?,?)
                ON CONFLICT(scope_key,principal_id,grant_key) DO UPDATE SET revision=excluded.revision,last_seq=excluded.last_seq,active=excluded.active
                WHERE grants.revision=excluded.revision-1",
        crate::sql_value::sql_params![x.s, x.actor(principal)?, codec::encode(grant)?, x.revision, x.seq, active],
    )
    .map_err(sql)?;
    Ok(())
}
fn change_captain(x: Ctx<'_>, target: &ProjectId, captain: Option<Actor>) -> StoreResult<()> {
    let (c, header, seq, revision) = (x.c, x.header, x.seq, x.revision);
    let p = x.project()?;
    if key(c, "project", target.as_str(), &[0], false)? != p || !project::is_owner(c, header, p)? {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "only the project owner can change its captain",
        ));
    }
    match captain {
        Some(Actor::Agent(ref agent)) => {
            let principal = x.actor(&Actor::Agent(agent.clone()))?;
            let exists: bool = c.query_row("SELECT EXISTS(SELECT 1 FROM principals WHERE project_id=? AND principal_id=? AND principal_kind='agent')", rusqlite::params![p, principal], |r| r.get(0)).map_err(sql)?;
            if !exists {
                return Err(fail(
                    StoreErrorCode::ReferenceMissing,
                    "choose a registered project agent",
                ));
            }
            principal::refuse_retired(c, p, &principal)?;
        }
        Some(Actor::Human(ref human)) if header.actor == Actor::Human(human.clone()) => {}
        Some(_) => {
            return Err(fail(
                StoreErrorCode::ScopeMismatch,
                "captain must be the project owner or a registered project agent",
            ));
        }
        None => assignment::require_closed(c, p)?,
    }
    let changed = c.execute("INSERT INTO project_captain(project_id,revision,last_seq) VALUES(?,?,?) ON CONFLICT(project_id) DO UPDATE SET revision=excluded.revision,last_seq=excluded.last_seq WHERE project_captain.revision=excluded.revision-1", crate::sql_value::sql_params![p,revision,seq]).map_err(sql)?;
    if changed != 1 {
        return Err(fail(
            StoreErrorCode::InvalidTransition,
            "captain revision changed before update",
        ));
    }
    Ok(())
}
fn register_project(x: Ctx<'_>, body: EventBody<InputText>) -> StoreResult<()> {
    let (c, header, seq, revision) = (x.c, x.header, x.seq, x.revision);
    let EventBody::ProjectRegistered {
        project: p,
        roots,
        owner,
        ..
    } = body
    else {
        return later("projection");
    };
    if header.actor != Actor::Human(owner.clone()) {
        return Err(fail(
            StoreErrorCode::ScopeMismatch,
            "project registration actor must be its admitted owner",
        ));
    }
    let p = key(c, "project", p.as_str(), &[0], true)?;
    if x.pk.is_some_and(|scope| scope != p.as_slice()) {
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
        c.execute(
            "INSERT INTO roots(project_id,canonical_key,encoded_path,last_seq) VALUES(?,?,?,?)",
            crate::sql_value::sql_params![p, root.canonical_key, encoded, seq],
        )
        .map_err(sql)?;
    }
    Ok(())
}
const MESSAGE_KINDS: [&str; 8] = [
    "note", "task", "question", "answer", "blocker", "done", "handoff", "finding",
];
fn send_message(x: Ctx<'_>, body: EventBody<InputText>) -> StoreResult<()> {
    let (c, header, s, seq, revision) = (x.c, x.header, x.s, x.seq, x.revision);
    let EventBody::MessageSent {
        message,
        recipient,
        kind,
        body,
        refs,
        reply_to,
        quiet,
    } = body
    else {
        return later("projection");
    };
    notification::require_schema(c, quiet)?;
    if refs.len() > 64 || !MESSAGE_KINDS.contains(&kind.as_str()) {
        return Err(invalid("message refs/kind bounds"));
    }
    let m = key(c, "message", message.as_str(), s, true)?;
    let remote_reply = crate::remote::reply_route(c, header, &recipient, reply_to.as_ref())?;
    if remote_reply.is_some() && codec::encode(&body.as_materialized()?)?.len() > 40 * 1024 {
        return Err(invalid(
            "encoded remote reply exceeds its delivery frame; send a shorter reply",
        ));
    }
    mail_rate::direct(c, header, x.project()?, s, &header.actor, &recipient)?;
    let recipient = x.actor(&recipient)?;
    let sender = x.actor(&header.actor)?;
    let exists: bool = c
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM principals WHERE project_id=? AND principal_id=?)",
            crate::sql_value::sql_params![x.project()?, recipient],
            |r| crate::sql_value::value(r, 0),
        )
        .map_err(sql)?;
    if !exists && remote_reply.is_none() {
        return Err(fail(
            StoreErrorCode::ReferenceMissing,
            "message recipient is not registered in this project",
        ));
    }
    if exists {
        principal::refuse_retired(c, x.project()?, &recipient)?;
    }
    let body = payload(
        c,
        seq,
        "body",
        &codec::text(body.as_materialized()?, se_types::MESSAGE_BODY_MAX_BYTES)?,
    )?;
    let reply = reply_to
        .map(|id| key(c, "message", id.as_str(), s, false))
        .transpose()?;
    message_refs(x, &refs)?;
    let schema_version = connection::info(c)?.schema_version;
    let message_insert = if schema_version >= 4 {
        format!(
            "INSERT INTO message_data(event_seq,message_id,recipient_id,message_kind,body_payload,refs,reply_to,quiet) VALUES(?,?,?,?,?,?,?,{})",
            u8::from(quiet)
        )
    } else {
        "INSERT INTO message_data(event_seq,message_id,recipient_id,message_kind,body_payload,refs,reply_to) VALUES(?,?,?,?,?,?,?)".into()
    };
    c.execute(
        &message_insert,
        crate::sql_value::sql_params![seq, m, recipient, kind, body, codec::encode(&refs)?, reply],
    )
    .map_err(sql)?;
    message_rows(x, schema_version, &m, &sender, &recipient, &kind)?;
    let is_remote_reply = remote_reply.is_some();
    crate::remote::enqueue_reply(c, remote_reply, x.project()?, &m, seq)?;
    notification::sent(c, seq, &recipient, quiet)?;
    if !is_remote_reply {
        count(c, x.project()?, &recipient, 1, seq)?;
    }
    if let Some(old) = &header.supersedes {
        message::supersede_from_header(c, header, old, &message, seq, revision)?;
    }
    Ok(())
}
/// Every message ref names an event already committed in this project.
fn message_refs(x: Ctx<'_>, refs: &[se_types::EventId]) -> StoreResult<()> {
    for r in refs {
        let k = key(x.c, "event", r.as_str(), x.s, false)?;
        let ok: bool =
            x.c.query_row(
                "SELECT EXISTS(SELECT 1 FROM events WHERE project_id=? AND event_id=?)",
                crate::sql_value::sql_params![x.project()?, k],
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
    Ok(())
}
/// The message head, the recipient's mark and, where present, its delivery row.
fn message_rows(
    x: Ctx<'_>,
    schema_version: u32,
    m: &[u8],
    sender: &[u8],
    recipient: &[u8],
    kind: &str,
) -> StoreResult<()> {
    let (c, seq, revision) = (x.c, x.seq, x.revision);
    // Schema 15 added the append-stamp column; direct writes to older
    // homes keep the pre-15 row shape and count through the events
    // stamp until a host open migrates them.
    if schema_version >= 15 {
        let recorded: i64 = c
            .query_row(
                "SELECT recorded_at_us FROM events WHERE seq=?",
                [seq],
                |r| r.get(0),
            )
            .map_err(sql)?;
        c.execute("INSERT INTO messages(project_id,message_id,sent_seq,sender_id,recipient_id,message_kind,recorded_at_us,revision)
                        VALUES(?,?,?,?,?,?,?,?)",crate::sql_value::sql_params![x.project()?,m,seq,sender,recipient,kind,recorded,revision]).map_err(sql)?;
    } else {
        c.execute("INSERT INTO messages(project_id,message_id,sent_seq,sender_id,recipient_id,message_kind,revision)
                        VALUES(?,?,?,?,?,?,?)",crate::sql_value::sql_params![x.project()?,m,seq,sender,recipient,kind,revision]).map_err(sql)?;
    }
    c.execute(
        "INSERT INTO marks(message_seq,project_id,recipient_id) VALUES(?,?,?)",
        crate::sql_value::sql_params![seq, x.project()?, recipient],
    )
    .map_err(sql)?;
    if connection::mail_table(c)? == "message_deliveries" {
        c.execute("INSERT INTO message_deliveries(project_id,message_id,sent_seq,sender_id,recipient_id,message_kind,is_floor,revision) VALUES(?,?,?,?,?,?,0,?)",crate::sql_value::sql_params![x.project()?,m,seq,sender,recipient,kind,revision]).map_err(sql)?;
    }
    Ok(())
}
fn set_working_state(x: Ctx<'_>, body: EventBody<InputText>) -> StoreResult<()> {
    let (c, s, seq, revision) = (x.c, x.s, x.seq, x.revision);
    let EventBody::WorkingStateSet {
        agent,
        text,
        expected: want,
    } = body
    else {
        return later("projection");
    };
    let a = key(c, "agent", agent.as_str(), s, true)?;
    let p = payload(
        c,
        seq,
        "body",
        &codec::text(text.as_materialized()?, se_types::WORKING_STATE_MAX_BYTES)?,
    )?;
    let want = match want {
        Expected::Absent => None,
        Expected::Revision(r) => Some(r.value.get()),
    };
    c.execute("INSERT INTO working_state_data(event_seq,agent_id,text_payload,expected_revision) VALUES(?,?,?,?)",crate::sql_value::sql_params![seq,a,p,want]).map_err(sql)?;
    c.execute("INSERT INTO working_state(project_id,agent_id,revision,last_seq) VALUES(?,?,?,?) ON CONFLICT(project_id,agent_id)
                    DO UPDATE SET revision=excluded.revision,last_seq=excluded.last_seq WHERE working_state.revision=excluded.revision-1",crate::sql_value::sql_params![x.project()?,a,revision,seq]).map_err(sql)?;
    let changed=c.execute("UPDATE resume_heads SET last_working_state_seq=?,last_seq=? WHERE project_id=? AND principal_id=?",crate::sql_value::sql_params![seq,seq,x.project()?,a]).map_err(sql)?;
    if changed != 1 {
        return Err(fail(
            StoreErrorCode::ProjectionInconsistent,
            "working-state resume head absent",
        ));
    }
    Ok(())
}
fn runtime_owner(x: Ctx<'_>, body: EventBody<InputText>, lease: &LeaseIdentity) -> StoreResult<()> {
    let (c, seq, revision) = (x.c, x.seq, x.revision);
    let EventBody::RuntimeOwnerEstablished {
        epoch,
        generation,
        expected_owner_generation,
        recovered,
        ..
    } = body
    else {
        return later("projection");
    };
    if recovered.is_some() {
        return later("recovered runtime ownership projection");
    }
    if x.pk.is_some() || lease.mode != LeaseMode::Host || lease.generation != generation.get() {
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
