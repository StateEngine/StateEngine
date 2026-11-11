//! Two-stage compatibility witness: a historical writer produces the database;
//! a candidate host migrates a private copy without rewriting retained history.
//! Both stages are opt-in and require an evidence directory outside the checkout.
#![cfg(any(target_os = "linux", windows))]

#[path = "support/store_fixture.rs"]
mod fixture;

use fixture::{Check, Fixture, Lease, message, present, request};
use rusqlite::{Connection as Database, OpenFlags, types::ValueRef};
use se_proc::NativeStateFiles;
use se_store::{
    channel::{Change, ChannelId, OutputId, Pairing, ReceiptId},
    *,
};
use se_types::{AgentId, EventId, HumanId, MessageId, ProjectId};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    error::Error,
    fs,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

type Fallible<T> = Result<T, Box<dyn Error>>;
const BOT: i64 = 4_294_967_311;
const SUBJECT: i64 = 4_294_967_331;
const UPDATE: i64 = 2_147_483_619;
const FIRST_PROVIDER_MESSAGE: i64 = 8_589_934_600;
const INPUT: &str = "Retain this original across a schema upgrade.";
const REPLY: &str = "This is the exact recipient's linked reply.";

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
enum Cell {
    Null,
    Integer(i64),
    RealBits(u64),
    Text(Vec<u8>),
    Blob(Vec<u8>),
}
type History = BTreeMap<String, Vec<Vec<Cell>>>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyEvent {
    id: EventId,
    change: Value,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedOutput {
    id: OutputId,
    kind: String,
    original: Option<MessageId>,
    reply: Option<MessageId>,
    provider_message: i64,
    completed: EventId,
    at_us: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: u32,
    schema: u32,
    store: StoreId,
    owner: HumanId,
    project: ProjectId,
    recipient: AgentId,
    connection: ChannelId,
    connection_json: Value,
    receipt: ReceiptId,
    original: MessageId,
    original_event: EventId,
    saved_event: EventId,
    saved_ordinal: u64,
    saved_at_us: i64,
    read_event: EventId,
    reply: MessageId,
    reply_event: EventId,
    outputs: Vec<AcceptedOutput>,
    legacy_events: Vec<LegacyEvent>,
    history: History,
    database_sha256: [u8; 32],
}

fn evidence_path(variable: &str) -> Fallible<PathBuf> {
    let path = PathBuf::from(std::env::var_os(variable).ok_or(variable.to_owned())?);
    if !path.is_absolute() {
        return Err("the evidence directory must be an explicit absolute path".into());
    }
    let parent = path
        .parent()
        .ok_or("evidence parent absent")?
        .canonicalize()?;
    let path = parent.join(path.file_name().ok_or("evidence directory name absent")?);
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .ok_or("workspace ancestor absent")?
        .canonicalize()?;
    if path.starts_with(workspace) {
        return Err("historical database evidence must stay outside the checkout".into());
    }
    Ok(path)
}

fn read_owned(files: &NativeStateFiles, path: &Path) -> Fallible<Vec<u8>> {
    let mut file = files.readback(path)?.ok_or("owned evidence file absent")?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn publish(files: &NativeStateFiles, name: &str, bytes: &[u8]) -> Check {
    let mut staged = files.create_staging(files.root())?;
    staged.file.write_all(bytes)?;
    staged.file.sync_all()?;
    drop(staged.file);
    files.publish_no_replace(&staged.path, &files.root().join(name))?;
    assert_eq!(read_owned(files, &files.root().join(name))?, bytes);
    Ok(())
}

fn database(path: &Path) -> Fallible<Database> {
    Ok(Database::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?)
}

// Capture SQLite values, not a reserialization of decoded event structs. Text
// and blob bytes remain distinct; integer coordinates are never round-tripped
// through floating-point JSON. Include the event envelopes and owning payloads.
fn history(db: &Database) -> Fallible<History> {
    let mut result = BTreeMap::new();
    for (table, order) in [
        ("events", "seq"),
        ("aux_data", "event_seq"),
        ("payloads", "payload_id"),
        ("message_data", "event_seq"),
        ("mark_data", "event_seq"),
        ("operations", "operation_id"),
        ("operation_events", "operation_id,ordinal"),
    ] {
        let mut query = db.prepare(&format!("SELECT * FROM {table} ORDER BY {order}"))?;
        let columns = query.column_count();
        let mut rows = query.query([])?;
        let mut values = Vec::new();
        while let Some(row) = rows.next()? {
            let mut cells = Vec::new();
            for column in 0..columns {
                cells.push(match row.get_ref(column)? {
                    ValueRef::Null => Cell::Null,
                    ValueRef::Integer(value) => Cell::Integer(value),
                    ValueRef::Real(value) => Cell::RealBits(value.to_bits()),
                    ValueRef::Text(value) => Cell::Text(value.to_vec()),
                    ValueRef::Blob(value) => Cell::Blob(value.to_vec()),
                });
            }
            values.push(cells);
        }
        result.insert(table.into(), values);
    }
    Ok(result)
}

fn require_legacy_database(db: &Database) -> Check {
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))?,
        8
    );
    let coordinates: (String, String, String, String) = db.query_row(
        "SELECT typeof(bot_id),json_type(state_json,'$.bot.id'),
         json_type(state_json,'$.pairing.phone.subject'),
         json_type(state_json,'$.pairing.phone.private_chat') FROM channel_connections",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    assert_eq!(
        coordinates,
        (
            "integer".into(),
            "integer".into(),
            "integer".into(),
            "integer".into()
        )
    );
    let updates: i64 = db.query_row(
        "SELECT count(*) FROM channel_updates WHERE typeof(update_id)='integer'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(updates, 2);
    let integer_events: i64 = db.query_row(
        "SELECT count(*) FROM aux_data WHERE json_type(facts,'$.change.update')='integer'",
        [],
        |r| r.get(0),
    )?;
    assert_eq!(integer_events, 2);
    let accepted: i64 = db.query_row(
        "SELECT count(*) FROM channel_outbox WHERE state='sent' AND typeof(provider_message)='integer'",
        [], |r| r.get(0),
    )?;
    assert_eq!(accepted, 5);
    Ok(())
}

fn channel_batch(f: &Fixture, change: Value, key: &str) -> Fallible<AtomicBatch> {
    let change: Change = serde_json::from_value(change)?;
    let mut batch = f.batch(
        f.owner_project(),
        Some(request(key)?),
        vec![EventBody::ChannelRecorded { change }],
    )?;
    for event in &mut batch.events {
        event.header.door = Door::Host;
    }
    Ok(batch)
}

fn append_channel(
    f: &Fixture,
    writer: &mut SqliteDirect,
    lease: &Lease,
    retained: &mut Vec<LegacyEvent>,
    change: Value,
    key: &str,
) -> Fallible<CommitReceipt> {
    let batch = channel_batch(f, change.clone(), key)?;
    let id = batch.events[0].header.event.clone();
    let receipt = writer.append(batch, lease)?;
    retained.push(LegacyEvent { id, change });
    Ok(receipt)
}

#[test]
#[ignore = "run on the historical revision with SE_CHANNEL_UPGRADE_PRODUCE set"]
#[expect(
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn produce_schema_eight() -> Check {
    let root = evidence_path("SE_CHANNEL_UPGRADE_PRODUCE")?;
    match fs::symlink_metadata(&root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
        Ok(_) => return Err("producer refuses an existing evidence directory".into()),
    }
    let f = Fixture::new()?;
    let (mut writer, lease) = f.direct()?;
    assert_eq!(
        writer.info()?.schema_version,
        8,
        "producer must run on the historical writer"
    );
    let connection = ChannelId::new("chn-71717171717171717171717171717171")?;
    let receipt = ReceiptId::new("chr-72727272727272727272727272727272")?;
    let original = message()?;
    let reply = message()?;
    let expires = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros())?
        .checked_add(3_600_000_000)
        .ok_or("expiry overflow")?;
    let phone = json!({
        "subject": SUBJECT, "private_chat": SUBJECT,
        "display_name": "Fixture sender", "username": null,
    });
    // Deliberately omit the future connector/cursor fields and retain integers.
    let initial = json!({
        "id": connection, "owner": f.owner,
        "credential": {"store": f.store, "owner": f.owner,
            "id": "ccr-73737373737373737373737373737373", "revision": 1},
        "target": {"project": f.project, "agent": f.a, "selection_revision": 1},
        "bot": {"id": BOT, "username": "upgrade_fixture_bot", "display_name": "Fixture bot"},
        "policy": {"kind": "save_only"},
        "pairing": {"kind": "challenge", "digest": vec![19u8; 32], "expires_at_us": expires},
        "revision": 1, "credential_removed": false, "resume_configuration": null,
    });
    let mut retained = Vec::new();
    for (change, key) in [
        (
            json!({"kind": "connected", "connection": initial}),
            "upgrade-connect",
        ),
        (
            json!({"kind": "pairing_seen", "connection": connection, "expected": 1,
            "digest": vec![19u8; 32], "phone": phone}),
            "upgrade-seen",
        ),
        (
            json!({"kind": "pairing_confirmed", "connection": connection, "expected": 2}),
            "upgrade-confirm",
        ),
    ] {
        append_channel(&f, &mut writer, &lease, &mut retained, change, key)?;
    }
    writer.append(
        f.batch(
            f.owner_project(),
            Some(request("upgrade-project-owner")?),
            vec![EventBody::PrincipalRegistered {
                principal: Actor::Human(f.owner.clone()),
                kind: PrincipalKind::Human,
                owner: f.owner.clone(),
                created_by: None,
                name: "Fixture owner".into(),
                role: "owner".into(),
                expected: Expected::Absent,
            }],
        )?,
        &*lease,
    )?;
    let saved = json!({
        "kind": "update_handled", "connection": connection, "binding_revision": 3,
        "update": UPDATE, "disposition": {"kind": "saved", "receipt": receipt,
            "message": original, "subject": SUBJECT, "private_chat": SUBJECT},
    });
    let mut batch = f.send(
        Actor::Human(f.owner.clone()),
        Actor::Agent(f.a.clone()),
        original.clone(),
        INPUT,
        "upgrade-save",
    )?;
    let original_event = batch.events[0].header.event.clone();
    let mut metadata = channel_batch(&f, saved.clone(), "unused-save-metadata")?;
    let saved_event = metadata.events[0].header.event.clone();
    batch.events.append(&mut metadata.events);
    for event in &mut batch.events {
        event.header.door = Door::Host;
    }
    writer.append(batch, &*lease)?;
    retained.push(LegacyEvent {
        id: saved_event.clone(),
        change: saved,
    });

    let read = writer.append(
        f.batch(
            f.admission(Scope::Project(f.project.clone()), Actor::Agent(f.a.clone())),
            Some(request("upgrade-recipient-read")?),
            vec![EventBody::MessageRead {
                message: original.clone(),
                recipient: Actor::Agent(f.a.clone()),
            }],
        )?,
        &*lease,
    )?;
    let mut batch = f.send(
        Actor::Agent(f.a.clone()),
        Actor::Human(f.owner.clone()),
        reply.clone(),
        REPLY,
        "upgrade-linked-reply",
    )?;
    let EventBody::MessageSent { reply_to, .. } = &mut batch.events[0].body else {
        return Err("expected ordinary reply batch".into());
    };
    *reply_to = Some(original.clone());
    let replied = writer.append(batch, &*lease)?;
    append_channel(
        &f,
        &mut writer,
        &lease,
        &mut retained,
        json!({
            "kind": "update_handled", "connection": connection, "binding_revision": 3,
            "update": UPDATE + 1, "disposition": {"kind": "rejected_paired",
                "reason": "unsupported", "subject": SUBJECT, "private_chat": SUBJECT},
        }),
        "upgrade-reject",
    )?;

    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    let queued = view.channel_outbox(&connection, 0)?;
    assert_eq!(queued.omitted, 0);
    assert_eq!(queued.items.len(), 5);
    view.close()?;
    let mut outputs = Vec::new();
    for (index, output) in queued.items.into_iter().enumerate() {
        let provider_message = FIRST_PROVIDER_MESSAGE + i64::try_from(index)?;
        append_channel(
            &f,
            &mut writer,
            &lease,
            &mut retained,
            json!({
                "kind": "output_started", "connection": connection, "binding_revision": 3,
                "output": output.output, "expected_attempt": 0,
            }),
            &format!("upgrade-output-start-{index}"),
        )?;
        let completed = append_channel(
            &f,
            &mut writer,
            &lease,
            &mut retained,
            json!({
                "kind": "output_finished", "connection": connection, "output": output.output,
                "attempt": 1, "outcome": {"kind": "sent", "provider_message": provider_message},
            }),
            &format!("upgrade-output-finish-{index}"),
        )?;
        let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
        let at_us = present(view.event(completed.primary_event.clone())?)?.recorded_at_us;
        view.close()?;
        outputs.push(AcceptedOutput {
            id: output.output,
            kind: output.kind,
            original: output.original,
            reply: output.reply,
            provider_message,
            completed: completed.primary_event,
            at_us,
        });
    }
    let mut view = writer.snapshot(f.scoped(Visibility::Owner))?;
    let connection_json = serde_json::to_value(present(view.channel_connection(&connection)?)?)?;
    assert!(connection_json["bot"]["id"].is_i64());
    assert!(connection_json.get("connector").is_none());
    let saved = present(view.channel_receipt(&connection, &receipt)?)?;
    assert_eq!(saved.event, saved_event);
    assert_eq!(saved.message, original);
    view.close()?;
    writer.close()?;
    drop(lease);

    let path = f.options.state_directory.join("state.db");
    let db = database(&path)?;
    require_legacy_database(&db)?;
    let history = history(&db)?;
    db.close().map_err(|(_, error)| error)?;
    let files = NativeStateFiles::open(&f.options.state_directory)?;
    if let Some(wal) = files.readback(&f.options.state_directory.join("state.db-wal"))? {
        assert_eq!(
            wal.metadata()?.len(),
            0,
            "export requires a fully closed database"
        );
    }
    let bytes = read_owned(&files, &path)?;
    let manifest = Manifest {
        format: 1,
        schema: 8,
        store: f.store.clone(),
        owner: f.owner.clone(),
        project: f.project.clone(),
        recipient: f.a.clone(),
        connection,
        connection_json,
        receipt,
        original,
        original_event,
        saved_event,
        saved_ordinal: saved.ordinal,
        saved_at_us: saved.at_us,
        read_event: read.primary_event,
        reply,
        reply_event: replied.primary_event,
        outputs,
        legacy_events: retained,
        history,
        database_sha256: Sha256::digest(&bytes).into(),
    };
    let evidence = NativeStateFiles::create(&root)?;
    let state = NativeStateFiles::create(&root.join("state"))?;
    publish(&state, "state.db", &bytes)?;
    publish(
        &evidence,
        "manifest.json",
        &serde_json::to_vec_pretty(&manifest)?,
    )?;
    eprintln!(
        "Closed schema-eight fixture published at {}",
        root.display()
    );
    Ok(())
}

#[expect(
    clippy::cognitive_complexity,
    clippy::too_many_lines,
    reason = "pre-existing at guardrail establishment; delete this expect when the lint is fixed"
)]
fn check_public_readback(view: &mut SqliteSnapshot, m: &Manifest) -> Check {
    let state = present(view.channel_connection(&m.connection)?)?;
    let expected: channel::Connection = serde_json::from_value(m.connection_json.clone())?;
    assert_eq!(state, expected);
    assert_eq!(state.bot.id.to_string(), BOT.to_string());
    let Pairing::Paired { phone } = &state.pairing else {
        return Err("historical Telegram pairing was not retained".into());
    };
    assert_eq!(phone.subject.to_string(), SUBJECT.to_string());
    assert_eq!(phone.private_chat.to_string(), SUBJECT.to_string());
    assert_eq!(state.revision, 3);
    assert!(!state.credential_removed);
    assert_eq!(view.channel_active()?, vec![state.clone()]);
    let listed = view.channel_connections(0)?;
    assert_eq!(listed.omitted, 0);
    assert_eq!(listed.items, vec![state]);

    let saved = present(view.channel_receipt(&m.connection, &m.receipt)?)?;
    assert_eq!(saved.connection, m.connection);
    assert_eq!(saved.receipt, m.receipt);
    assert_eq!(saved.message, m.original);
    assert_eq!(saved.event, m.saved_event);
    assert_eq!(saved.ordinal, m.saved_ordinal);
    assert_eq!(saved.at_us, m.saved_at_us);
    let saved_page = view.channel_saved(&m.connection, 0)?;
    assert_eq!(saved_page.omitted, 0);
    assert_eq!(saved_page.items.len(), 1);
    assert_eq!(saved_page.items[0].receipt, m.receipt);
    assert_eq!(saved_page.items[0].message, m.original);
    assert_eq!(saved_page.items[0].event, m.saved_event);

    let original = present(view.message(m.original.clone())?)?;
    assert_eq!(original.event, m.original_event);
    assert_eq!(original.sender, Actor::Human(m.owner.clone()));
    assert_eq!(original.recipient, Actor::Agent(m.recipient.clone()));
    assert!(matches!(&original.body, StoredText::Present(text) if text == INPUT));
    assert!(original.body_complete);
    assert!(
        original.delivered.is_none(),
        "read is not invented delivery evidence"
    );
    assert!(original.dismissed.is_none());
    let read = present(view.event(m.read_event.clone())?)?;
    assert_eq!(original.read.as_ref(), Some(&read.position));
    assert_eq!(read.header.actor, Actor::Agent(m.recipient.clone()));
    assert!(
        matches!(read.body, EventBody::MessageRead { message, recipient }
        if message == m.original && recipient == Actor::Agent(m.recipient.clone()))
    );
    let reply = present(view.message(m.reply.clone())?)?;
    assert_eq!(reply.event, m.reply_event);
    assert_eq!(reply.sender, Actor::Agent(m.recipient.clone()));
    assert_eq!(reply.recipient, Actor::Human(m.owner.clone()));
    assert_eq!(reply.reply_to.as_ref(), Some(&m.original));
    assert!(matches!(&reply.body, StoredText::Present(text) if text == REPLY));
    assert!(reply.body_complete);
    let route = view
        .channel_reply_route(&m.original)?
        .ok_or("reply route absent")?;
    assert!(route.active);
    assert_eq!(route.owner, m.owner);
    assert_eq!(route.original, m.original);
    let replies = view.channel_replies(&m.connection, &m.original)?;
    assert_eq!(replies.omitted, 0);
    assert_eq!(replies.items.len(), 1);
    assert_eq!(replies.items[0].reply.as_ref(), Some(&m.reply));

    let outputs = view.channel_outbox(&m.connection, 0)?;
    assert_eq!(outputs.omitted, 0);
    assert_eq!(outputs.items.len(), m.outputs.len());
    assert_eq!(m.outputs.len(), 5);
    for expected in &m.outputs {
        let output = outputs
            .items
            .iter()
            .find(|o| o.output == expected.id)
            .ok_or("accepted historical output disappeared")?;
        assert_eq!(output.connection, m.connection);
        assert_eq!(output.kind, expected.kind);
        assert_eq!(output.original, expected.original);
        assert_eq!(output.reply, expected.reply);
        assert_eq!(output.state, "sent");
        assert_eq!(output.attempt, 1);
        assert_eq!(output.binding_revision, 3);
        assert_eq!(output.at_us, expected.at_us);
        assert_eq!(
            output.provider_message.as_ref().map(ToString::to_string),
            Some(expected.provider_message.to_string())
        );
        assert_eq!(
            output.provider_update.as_ref().map(ToString::to_string),
            (expected.kind == "rejected").then(|| (UPDATE + 1).to_string())
        );
        assert!(output.failure.is_none());
        assert!(output.retry_at_us.is_none());
        let finished = present(view.event(expected.completed.clone())?)?;
        assert_eq!(finished.recorded_at_us, expected.at_us);
    }
    assert!(
        view.channel_pending_outputs(&m.connection, i64::MAX)?
            .items
            .is_empty()
    );
    let rejected = view.channel_recent_rejections(&m.connection)?;
    assert!(!rejected.more);
    assert_eq!(rejected.items.len(), 1);
    assert_eq!(
        rejected.items[0].update.to_string(),
        (UPDATE + 1).to_string()
    );
    assert_eq!(rejected.items[0].reason, channel::Rejection::Unsupported);
    assert_eq!(rejected.items[0].output_state, "sent");
    for legacy in &m.legacy_events {
        let event = present(view.event(legacy.id.clone())?)?;
        let EventBody::ChannelRecorded { change } = event.body else {
            return Err("historical event changed kind".into());
        };
        let expected: Change = serde_json::from_value(legacy.change.clone())?;
        assert_eq!(
            change, expected,
            "legacy integer event failed typed readback"
        );
    }
    Ok(())
}

#[test]
#[ignore = "run on the candidate with SE_CHANNEL_UPGRADE_CONSUME set"]
fn migrate_schema_eight_preserves_legacy_channels() -> Check {
    let root = evidence_path("SE_CHANNEL_UPGRADE_CONSUME")?;
    let evidence = NativeStateFiles::open(&root)?;
    let m: Manifest = serde_json::from_slice(&read_owned(&evidence, &root.join("manifest.json"))?)?;
    assert_eq!(m.format, 1);
    assert_eq!(m.schema, 8);
    let source = NativeStateFiles::open(&root.join("state"))?;
    let source_path = source.root().join("state.db");
    let bytes = read_owned(&source, &source_path)?;
    assert_eq!(<[u8; 32]>::from(Sha256::digest(&bytes)), m.database_sha256);
    let db = database(&source_path)?;
    require_legacy_database(&db)?;
    assert_eq!(
        history(&db)?,
        m.history,
        "source fixture differs from producer manifest"
    );
    db.close().map_err(|(_, error)| error)?;

    // Only migrate the private copy. The original remains reusable evidence.
    let mut f = Fixture::new()?;
    f.store = m.store.clone();
    f.owner = m.owner.clone();
    f.project = m.project.clone();
    f.a = m.recipient.clone();
    let destination = NativeStateFiles::open(&f.options.state_directory)?;
    publish(&destination, "state.db", &bytes)?;
    let lease = Lease::acquire_with_backup_ports(
        &f.options.state_directory,
        LeaseMode::Host,
        Some(m.store.clone()),
        true,
    )?;
    let host = present(SqliteFactory::open_host(&f.options, &*lease)?)?;
    assert_eq!(
        host.info()?.schema_version,
        9,
        "consumer must migrate to the candidate schema"
    );
    assert_eq!(host.info()?.id, m.store);
    let mut view = host.snapshot(f.scoped(Visibility::Owner))?;
    check_public_readback(&mut view, &m)?;
    view.close()?;
    drop(host);
    drop(lease);

    let db = database(&f.options.state_directory.join("state.db"))?;
    assert_eq!(
        history(&db)?,
        m.history,
        "migration rewrote historical event envelopes, serialized facts, payloads, or operation receipts"
    );
    let checkpoint: (String, String, String) = db.query_row(
        "SELECT connector,bot_id,cursor FROM channel_receive",
        [],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    assert_eq!(
        checkpoint,
        ("telegram".into(), BOT.to_string(), (UPDATE + 1).to_string())
    );
    for expected in &m.outputs {
        let messages: String = db.query_row(
            "SELECT provider_messages FROM channel_outbox WHERE output_id=?",
            [expected.id.as_str()],
            |r| r.get(0),
        )?;
        assert_eq!(
            serde_json::from_str::<Vec<String>>(&messages)?,
            vec![expected.provider_message.to_string()]
        );
    }
    let violations: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
        [],
        |r| r.get(0),
    )?;
    assert!(!violations);
    assert_eq!(
        db.query_row("PRAGMA integrity_check", [], |r| r.get::<_, String>(0))?,
        "ok"
    );
    db.close().map_err(|(_, error)| error)?;
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(read_owned(&source, &source_path)?)),
        m.database_sha256,
        "consumer modified its historical source fixture"
    );
    Ok(())
}
