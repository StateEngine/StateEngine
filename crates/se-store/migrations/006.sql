-- Non-secret transport metadata. Mail bodies and replies remain ordinary mail.
CREATE TABLE channel_connections (
  id TEXT PRIMARY KEY,
  project_id BLOB NOT NULL,
  owner_id BLOB NOT NULL,
  bot_id INTEGER NOT NULL CHECK(bot_id > 0),
  credential_id TEXT NOT NULL,
  credential_revision INTEGER NOT NULL CHECK(credential_revision > 0),
  revision INTEGER NOT NULL CHECK(revision > 0),
  active INTEGER NOT NULL CHECK(active IN (0,1)),
  credential_removed INTEGER NOT NULL CHECK(credential_removed IN (0,1)),
  state_json TEXT NOT NULL,
  saved_count INTEGER NOT NULL DEFAULT 0 CHECK(saved_count>=0),
  last_seq INTEGER NOT NULL REFERENCES events(seq)
) STRICT;
CREATE UNIQUE INDEX channel_active_bot ON channel_connections(bot_id) WHERE active=1;
-- A pending forget blocks reuse, even after the binding has been revoked.
CREATE UNIQUE INDEX channel_owned_credential ON channel_connections(credential_id) WHERE credential_removed=0;
CREATE INDEX channel_owner_page ON channel_connections(project_id, owner_id, last_seq);
CREATE TABLE channel_updates (
  bot_id INTEGER NOT NULL,
  update_id INTEGER NOT NULL CHECK(update_id >= 0),
  connection_id TEXT NOT NULL REFERENCES channel_connections(id),
  handled_seq INTEGER NOT NULL REFERENCES events(seq),
  disposition TEXT NOT NULL,
  receipt_id TEXT UNIQUE,
  message_id BLOB,
  pending INTEGER NOT NULL DEFAULT 0 CHECK(pending IN (0,1)),
  status_due_at_us INTEGER,
  PRIMARY KEY(connection_id, update_id)
) STRICT;
CREATE INDEX channel_pending_mail ON channel_updates(connection_id,handled_seq) WHERE pending=1;
CREATE INDEX channel_status_due ON channel_updates(connection_id,status_due_at_us,handled_seq) WHERE status_due_at_us IS NOT NULL;
CREATE INDEX channel_saved_page ON channel_updates(connection_id, handled_seq) WHERE receipt_id IS NOT NULL;
CREATE INDEX channel_mail_route ON channel_updates(message_id,connection_id) WHERE message_id IS NOT NULL;
-- Provider ACK progress survives connection replacement; dispositions do not.
CREATE INDEX channel_bot_ack ON channel_updates(bot_id,update_id);
CREATE TABLE channel_outbox (
  connection_id TEXT NOT NULL REFERENCES channel_connections(id),
  binding_revision INTEGER NOT NULL,
  output_id TEXT PRIMARY KEY,
  attempt INTEGER NOT NULL DEFAULT 0 CHECK(attempt>=0),
  kind TEXT NOT NULL CHECK(kind IN ('paired','saved','notice','read','delay','reply','resume','resume_status','resume_failed','rejected','reply_failed')),
  original_id BLOB,
  reply_id BLOB,
  provider_update INTEGER,
  queued_seq INTEGER NOT NULL REFERENCES events(seq),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  state TEXT NOT NULL CHECK(state IN ('queued','sending','sent','unknown','failed','revoked')),
  provider_message INTEGER,
  failure TEXT,
  retry_at_us INTEGER
) STRICT;
CREATE UNIQUE INDEX channel_output_once ON channel_outbox(connection_id,kind,coalesce(original_id,x''),coalesce(reply_id,x''),coalesce(provider_update,-1));
CREATE INDEX channel_outbox_kind ON channel_outbox(connection_id,kind,queued_seq);
CREATE INDEX channel_outbox_original ON channel_outbox(connection_id,original_id,queued_seq);
CREATE INDEX channel_outbox_pending ON channel_outbox(connection_id,queued_seq) WHERE state IN ('queued','sending');
CREATE TABLE channel_actions (
  id TEXT PRIMARY KEY,
  connection_id TEXT NOT NULL REFERENCES channel_connections(id),
  original_id BLOB NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('offered','confirmed','released','failed')),
  action_json TEXT NOT NULL,
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  UNIQUE(connection_id,original_id)
) STRICT;
CREATE INDEX channel_actions_pending ON channel_actions(connection_id,last_seq) WHERE state='confirmed';
PRAGMA user_version=6;
