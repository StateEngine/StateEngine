-- Turns an external harness or owner client publishes. Structural facts stay
-- after erasure; the one prose body payload and its digest are erasable.
CREATE TABLE published_turns(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  project_id BLOB NOT NULL CHECK(length(project_id)=16),
  agent_id BLOB NOT NULL CHECK(length(agent_id)=16),
  session_id BLOB NOT NULL CHECK(length(session_id)=16),
  conversation TEXT NOT NULL CHECK(length(conversation) BETWEEN 1 AND 256),
  harness TEXT NOT NULL CHECK(length(harness) BETWEEN 1 AND 64),
  model_provider TEXT NOT NULL CHECK(length(model_provider) BETWEEN 1 AND 64),
  model TEXT NOT NULL CHECK(length(model) BETWEEN 1 AND 128),
  vendor_turn TEXT NOT NULL CHECK(length(vendor_turn) BETWEEN 1 AND 256),
  occurred_at_us INTEGER NOT NULL CHECK(occurred_at_us>=0),
  role TEXT NOT NULL CHECK(role IN ('user','assistant','tool')),
  body_payload INTEGER UNIQUE REFERENCES payloads(payload_id),
  body_omitted_bytes INTEGER NOT NULL CHECK(body_omitted_bytes>=0),
  content_sha256 BLOB CHECK(content_sha256 IS NULL OR length(content_sha256)=32),
  content_verified INTEGER NOT NULL CHECK(content_verified IN (0,1)),
  input_tokens INTEGER CHECK(input_tokens IS NULL OR input_tokens>=0),
  output_tokens INTEGER CHECK(output_tokens IS NULL OR output_tokens>=0),
  cache_read_tokens INTEGER CHECK(cache_read_tokens IS NULL OR cache_read_tokens>=0),
  cache_write_tokens INTEGER CHECK(cache_write_tokens IS NULL OR cache_write_tokens>=0),
  cost_usd REAL CHECK(cost_usd IS NULL OR cost_usd>=0),
  files_changed INTEGER CHECK(files_changed IS NULL OR files_changed>=0),
  insertions INTEGER CHECK(insertions IS NULL OR insertions>=0),
  deletions INTEGER CHECK(deletions IS NULL OR deletions>=0),
  parent_session_id BLOB CHECK(parent_session_id IS NULL OR length(parent_session_id)=16),
  nested_agent TEXT CHECK(nested_agent IS NULL OR length(nested_agent) BETWEEN 1 AND 256),
  nesting_depth INTEGER CHECK(nesting_depth IS NULL OR nesting_depth BETWEEN 1 AND 64),
  UNIQUE(project_id,session_id,harness,vendor_turn),
  FOREIGN KEY(project_id,session_id) REFERENCES sessions(project_id,session_id)
) STRICT;
CREATE INDEX published_turns_agent_seq ON published_turns(project_id,agent_id,event_seq);
CREATE INDEX published_turns_session_seq ON published_turns(project_id,session_id,event_seq);
CREATE TRIGGER published_turns_no_update BEFORE UPDATE ON published_turns
WHEN NOT (NEW.event_seq=OLD.event_seq AND NEW.project_id=OLD.project_id
  AND NEW.agent_id=OLD.agent_id AND NEW.session_id=OLD.session_id
  AND NEW.conversation=OLD.conversation AND NEW.harness=OLD.harness
  AND NEW.model_provider=OLD.model_provider AND NEW.model=OLD.model
  AND NEW.vendor_turn=OLD.vendor_turn AND NEW.occurred_at_us=OLD.occurred_at_us
  AND NEW.role=OLD.role AND NEW.body_omitted_bytes=OLD.body_omitted_bytes
  AND NEW.content_verified=OLD.content_verified
  AND NEW.input_tokens IS OLD.input_tokens AND NEW.output_tokens IS OLD.output_tokens
  AND NEW.cache_read_tokens IS OLD.cache_read_tokens
  AND NEW.cache_write_tokens IS OLD.cache_write_tokens AND NEW.cost_usd IS OLD.cost_usd
  AND NEW.files_changed IS OLD.files_changed AND NEW.insertions IS OLD.insertions
  AND NEW.deletions IS OLD.deletions AND NEW.parent_session_id IS OLD.parent_session_id
  AND NEW.nested_agent IS OLD.nested_agent AND NEW.nesting_depth IS OLD.nesting_depth
  AND OLD.body_payload IS NOT NULL AND NEW.body_payload IS NULL AND NEW.content_sha256 IS NULL
  AND se_erase_body_allowed(OLD.event_seq,'body')=1)
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER published_turns_no_delete BEFORE DELETE ON published_turns
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
PRAGMA user_version=18;
