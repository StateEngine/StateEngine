-- Widen provider coordinates without changing historical event bytes or receipts.
CREATE TABLE channel_connections_neutral (
  id TEXT PRIMARY KEY,
  project_id BLOB NOT NULL,
  owner_id BLOB NOT NULL,
  connector TEXT NOT NULL,
  bot_id TEXT NOT NULL,
  credential_id TEXT NOT NULL,
  credential_revision INTEGER NOT NULL CHECK(credential_revision > 0),
  revision INTEGER NOT NULL CHECK(revision > 0),
  active INTEGER NOT NULL CHECK(active IN (0,1)),
  credential_removed INTEGER NOT NULL CHECK(credential_removed IN (0,1)),
  state_json TEXT NOT NULL,
  saved_count INTEGER NOT NULL DEFAULT 0 CHECK(saved_count>=0),
  last_seq INTEGER NOT NULL REFERENCES events(seq)
) STRICT;
-- A pending forget blocks reuse, even after the binding has been revoked.
CREATE TABLE channel_updates_neutral (
  bot_id TEXT NOT NULL,
  update_id TEXT NOT NULL,
  cursor TEXT,
  connection_id TEXT NOT NULL REFERENCES channel_connections(id),
  handled_seq INTEGER NOT NULL REFERENCES events(seq),
  disposition TEXT NOT NULL,
  receipt_id TEXT UNIQUE,
  message_id BLOB,
  pending INTEGER NOT NULL DEFAULT 0 CHECK(pending IN (0,1)),
  status_due_at_us INTEGER,
  PRIMARY KEY(connection_id, update_id)
) STRICT;
-- Provider ACK progress survives connection replacement; dispositions do not.
CREATE TABLE channel_outbox_neutral (
  connection_id TEXT NOT NULL REFERENCES channel_connections(id),
  binding_revision INTEGER NOT NULL,
  output_id TEXT PRIMARY KEY,
  attempt INTEGER NOT NULL DEFAULT 0 CHECK(attempt>=0),
  kind TEXT NOT NULL CHECK(kind IN ('paired','saved','notice','read','delay','reply','resume','resume_status','resume_failed','rejected','reply_failed')),
  original_id BLOB,
  reply_id BLOB,
  provider_update TEXT,
  queued_seq INTEGER NOT NULL REFERENCES events(seq),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  state TEXT NOT NULL CHECK(state IN ('queued','sending','sent','unknown','failed','revoked')),
  provider_message TEXT,
  provider_messages TEXT NOT NULL DEFAULT '[]',
  failure TEXT,
  retry_at_us INTEGER
) STRICT;
INSERT INTO channel_connections_neutral SELECT id,project_id,owner_id,'telegram',CAST(bot_id AS TEXT),credential_id,credential_revision,revision,active,credential_removed,state_json,saved_count,last_seq FROM channel_connections;
INSERT INTO channel_updates_neutral SELECT CAST(bot_id AS TEXT),CAST(update_id AS TEXT),NULL,connection_id,handled_seq,disposition,receipt_id,message_id,pending,status_due_at_us FROM channel_updates;
INSERT INTO channel_outbox_neutral SELECT connection_id,binding_revision,output_id,attempt,kind,original_id,reply_id,CAST(provider_update AS TEXT),queued_seq,last_seq,state,CAST(provider_message AS TEXT),CASE WHEN provider_message IS NULL THEN '[]' ELSE json_array(CAST(provider_message AS TEXT)) END,failure,retry_at_us FROM channel_outbox;
DROP TABLE channel_outbox;
DROP TABLE channel_updates;
DROP TABLE channel_connections;
ALTER TABLE channel_connections_neutral RENAME TO channel_connections;
ALTER TABLE channel_updates_neutral RENAME TO channel_updates;
ALTER TABLE channel_outbox_neutral RENAME TO channel_outbox;
CREATE UNIQUE INDEX channel_active_bot ON channel_connections(connector,bot_id) WHERE active=1;
CREATE UNIQUE INDEX channel_owned_credential ON channel_connections(credential_id) WHERE credential_removed=0;
CREATE INDEX channel_owner_page ON channel_connections(project_id, owner_id, last_seq);
CREATE INDEX channel_pending_mail ON channel_updates(connection_id,handled_seq) WHERE pending=1;
CREATE INDEX channel_status_due ON channel_updates(connection_id,status_due_at_us,handled_seq) WHERE status_due_at_us IS NOT NULL;
CREATE INDEX channel_saved_page ON channel_updates(connection_id, handled_seq) WHERE receipt_id IS NOT NULL;
CREATE INDEX channel_mail_route ON channel_updates(message_id,connection_id) WHERE message_id IS NOT NULL;
CREATE INDEX channel_bot_ack ON channel_updates(bot_id,handled_seq);
CREATE UNIQUE INDEX channel_output_once ON channel_outbox(connection_id,kind,coalesce(original_id,x''),coalesce(reply_id,x''),coalesce(provider_update,''));
CREATE INDEX channel_outbox_kind ON channel_outbox(connection_id,kind,queued_seq);
CREATE INDEX channel_outbox_original ON channel_outbox(connection_id,original_id,queued_seq);
CREATE INDEX channel_outbox_pending ON channel_outbox(connection_id,queued_seq) WHERE state IN ('queued','sending');
CREATE TABLE channel_receive (
  connector TEXT NOT NULL,
  bot_id TEXT NOT NULL,
  cursor TEXT NOT NULL,
  PRIMARY KEY(connector,bot_id)
) STRICT;
INSERT INTO channel_receive SELECT 'telegram',CAST(bot_id AS TEXT),CAST(max(CAST(update_id AS INTEGER)) AS TEXT) FROM channel_updates GROUP BY bot_id;
PRAGMA user_version=9;
