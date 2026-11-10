-- Remote authority is separate from local Owner and session credentials.
-- Only public authority and credential digests are persisted.
CREATE TABLE remote_grants(
  grant_id BLOB PRIMARY KEY CHECK(length(grant_id)=16),
  principal_id BLOB NOT NULL UNIQUE CHECK(length(principal_id)=16),
  device_id BLOB NOT NULL CHECK(length(device_id)=16),
  credential_sha256 TEXT NOT NULL CHECK(length(credential_sha256)<=256),
  host TEXT NOT NULL CHECK(length(host)<=256),
  store_id BLOB NOT NULL CHECK(length(store_id)=16),
  subject TEXT NOT NULL CHECK(length(subject)<=4096),
  scope TEXT NOT NULL CHECK(length(scope)<=65536),
  issued_at_us INTEGER NOT NULL,
  authority_revision INTEGER NOT NULL CHECK(authority_revision>0),
  state TEXT NOT NULL CHECK(state IN ('active','revoked')),
  last_use_at_us INTEGER NOT NULL CHECK(last_use_at_us>=issued_at_us),
  expires_at_us INTEGER NOT NULL CHECK(expires_at_us-last_use_at_us=2592000000000),
  lease_revision INTEGER NOT NULL CHECK(lease_revision>0),
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES events(seq)
) STRICT;
CREATE INDEX remote_grants_active ON remote_grants(expires_at_us) WHERE state='active';
CREATE TABLE remote_message_attribution(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  project_id BLOB NOT NULL,
  message_id BLOB NOT NULL CHECK(length(message_id)=16),
  grant_id BLOB NOT NULL REFERENCES remote_grants(grant_id),
  facts TEXT NOT NULL CHECK(length(facts)<=16384),
  UNIQUE(project_id,message_id)
) STRICT;
PRAGMA user_version=7;
-- Remote replay visits only its granted agent's session metadata after the cursor.
CREATE INDEX session_data_agent_seq ON session_data(agent_id,event_seq);
-- Scoped message replay includes dispositions authored by the other participant.
CREATE INDEX mark_data_message_seq ON mark_data(message_seq,event_seq);
-- Shared work dispositions remain private to their exact addressed recipient.
CREATE INDEX work_mark_recipient_seq ON work_mark_data(recipient_id,event_seq);
