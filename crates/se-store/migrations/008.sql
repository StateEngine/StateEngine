-- Preserve every existing row while admitting configured ACP sessions.

CREATE TABLE session_data_acp(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  session_id BLOB NOT NULL CHECK(length(session_id)=16),
  agent_id BLOB NOT NULL CHECK(length(agent_id)=16),
  provider TEXT NOT NULL CHECK(provider IN ('claude','codex','secode','acp')),
  native_ref INTEGER NOT NULL REFERENCES symbols(id),
  generation INTEGER NOT NULL CHECK(generation>0),
  consent TEXT NOT NULL CHECK(consent IN ('capture','suppressed')),
  state TEXT NOT NULL CHECK(state IN ('prepared','active','ended','revoked')),
  expected_revision INTEGER CHECK(expected_revision IS NULL OR expected_revision>0),
  incumbent_id BLOB CHECK(incumbent_id IS NULL OR length(incumbent_id)=16),
  incumbent_expected_revision INTEGER CHECK(incumbent_expected_revision IS NULL OR incumbent_expected_revision>0),
  process_id BLOB CHECK(process_id IS NULL OR length(process_id)=16),
  containment_fact TEXT CHECK(containment_fact IS NULL OR json_valid(containment_fact)),
  reason_payload INTEGER REFERENCES payloads(payload_id),
  witness_refs TEXT NOT NULL CHECK(json_valid(witness_refs))
) STRICT;
INSERT INTO session_data_acp SELECT * FROM session_data;
DROP TABLE session_data;
ALTER TABLE session_data_acp RENAME TO session_data;
CREATE INDEX session_data_agent_seq ON session_data(agent_id,event_seq);
CREATE TABLE turn_data_acp(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  turn_id BLOB NOT NULL CHECK(length(turn_id)=16),
  project_id BLOB NOT NULL CHECK(length(project_id)=16),
  agent_id BLOB NOT NULL CHECK(length(agent_id)=16),
  session_id BLOB NOT NULL CHECK(length(session_id)=16),
  provider TEXT NOT NULL CHECK(provider IN ('claude','codex','secode','acp')),
  vendor_ref TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('system','user','assistant','tool')),
  text_payload INTEGER UNIQUE REFERENCES payloads(payload_id),
  source_path INTEGER REFERENCES symbols(id),
  source_offset INTEGER CHECK(source_offset>=0),
  source_length INTEGER CHECK(source_length>=0),
  source_sha256 BLOB CHECK(source_sha256 IS NULL OR length(source_sha256)=32),
  UNIQUE(project_id,session_id,provider,vendor_ref),
  FOREIGN KEY(project_id,session_id) REFERENCES sessions(project_id,session_id)
) STRICT;
INSERT INTO turn_data_acp SELECT * FROM turn_data;
DROP TABLE turn_data;
ALTER TABLE turn_data_acp RENAME TO turn_data;
CREATE INDEX turn_data_agent_seq ON turn_data(project_id,agent_id,event_seq);
CREATE INDEX turn_data_session_seq ON turn_data(project_id,session_id,event_seq);
CREATE UNIQUE INDEX turn_data_id ON turn_data(project_id,turn_id);
CREATE TRIGGER session_data_no_update BEFORE UPDATE ON session_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER session_data_no_delete BEFORE DELETE ON session_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER turn_data_no_update BEFORE UPDATE ON turn_data
WHEN NOT (NEW.event_seq=OLD.event_seq AND NEW.turn_id=OLD.turn_id AND NEW.project_id=OLD.project_id
  AND NEW.agent_id=OLD.agent_id AND NEW.session_id=OLD.session_id AND NEW.provider=OLD.provider
  AND NEW.vendor_ref=OLD.vendor_ref AND NEW.role=OLD.role AND NEW.source_path IS OLD.source_path
  AND NEW.source_offset IS OLD.source_offset AND NEW.source_length IS OLD.source_length
  AND OLD.text_payload IS NOT NULL AND NEW.text_payload IS NULL AND NEW.source_sha256 IS NULL
  AND se_erase_body_allowed(OLD.event_seq,'body')=1)
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER turn_data_no_delete BEFORE DELETE ON turn_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
PRAGMA user_version=8;
