PRAGMA application_id=0x53454E47;
PRAGMA user_version=1;
CREATE TABLE store_info(
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  store_id BLOB NOT NULL CHECK(length(store_id)=16),
  incarnation INTEGER NOT NULL CHECK(incarnation>0),
  created_at_us INTEGER NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('ready','migrating','recovering','erasing'))
) STRICT;
-- Rebuildable per-user owner head; immutable authority is in runtime.* events/aux_data.
CREATE TABLE runtime_owner(
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  owner_generation INTEGER NOT NULL CHECK(owner_generation>0),
  owner_epoch TEXT NOT NULL CHECK(json_valid(owner_epoch)),
  transfer BLOB CHECK(transfer IS NULL OR length(transfer)=16),
  phase TEXT CHECK(phase IS NULL OR phase IN
    ('Prepared','Claimed','Finished','Aborted','Recovered')),
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL UNIQUE REFERENCES events(seq),
  CHECK((transfer IS NULL)=(phase IS NULL))
) STRICT;
CREATE TABLE symbols(id INTEGER PRIMARY KEY, value BLOB NOT NULL UNIQUE) STRICT;
CREATE TABLE identities(
  storage_key BLOB PRIMARY KEY CHECK(length(storage_key)=16),
  kind TEXT NOT NULL CHECK(kind IN ('project','agent','human','session','message','decision','event','launch','observation','store','lifecycle')),
  wire_id TEXT NOT NULL,
  scope_key BLOB NOT NULL,
  encoding TEXT NOT NULL CHECK(encoding IN ('legacy-shape','registered-exception')),
  registration_source BLOB,
  CHECK(length(wire_id)>0 AND length(CAST(wire_id AS BLOB))<=512),
  CHECK(encoding!='registered-exception' OR registration_source IS NOT NULL),
  UNIQUE(kind,scope_key,wire_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE events(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  event_id BLOB NOT NULL UNIQUE CHECK(length(event_id)=16),
  project_id BLOB CHECK(project_id IS NULL OR length(project_id)=16),
  actor_id BLOB NOT NULL CHECK(length(actor_id)=16),
  session_id BLOB CHECK(session_id IS NULL OR length(session_id)=16),
  origin_id BLOB NOT NULL CHECK(length(origin_id)=16),
  door TEXT NOT NULL CHECK(door IN ('cli','mcp','hook','host','import')),
  kind TEXT NOT NULL,
  schema_version INTEGER NOT NULL CHECK(schema_version>0),
  recorded_incarnation INTEGER NOT NULL CHECK(recorded_incarnation>0),
  entity_revision INTEGER NOT NULL CHECK(entity_revision>0),
  writer_mode TEXT NOT NULL CHECK(writer_mode IN ('host','direct')),
  host_generation INTEGER CHECK(host_generation>0),
  durability TEXT NOT NULL CHECK(durability IN ('normal','full')),
  operation_id BLOB NOT NULL REFERENCES operations(operation_id),
  occurred_at_us INTEGER NOT NULL,
  recorded_at_us INTEGER NOT NULL,
  cause_event_id BLOB CHECK(cause_event_id IS NULL OR length(cause_event_id)=16),
  supersedes_event_id BLOB CHECK(supersedes_event_id IS NULL OR length(supersedes_event_id)=16),
  CHECK((writer_mode='host' AND host_generation IS NOT NULL) OR (writer_mode='direct' AND host_generation IS NULL)),
  CHECK(kind!='session.turn' OR session_id IS NOT NULL)
) STRICT;
CREATE INDEX events_scope_seq ON events(project_id,seq);
CREATE INDEX events_actor_seq ON events(project_id,actor_id,seq);
CREATE INDEX events_session_seq ON events(project_id,session_id,seq);
CREATE TABLE operations(
  operation_id BLOB PRIMARY KEY CHECK(length(operation_id)=16),
  scope_key BLOB NOT NULL,
  actor_id BLOB NOT NULL CHECK(length(actor_id)=16),
  request_key TEXT CHECK(request_key IS NULL OR length(CAST(request_key AS BLOB)) BETWEEN 1 AND 512),
  fingerprint_codec INTEGER NOT NULL DEFAULT 1 CHECK(fingerprint_codec>0),
  fingerprint BLOB CHECK(fingerprint IS NULL OR length(fingerprint)=32),
  recorded_incarnation INTEGER NOT NULL CHECK(recorded_incarnation>0),
  writer_mode TEXT NOT NULL CHECK(writer_mode IN ('host','direct')),
  host_generation INTEGER CHECK(host_generation>0),
  durability TEXT NOT NULL CHECK(durability IN ('normal','full')),
  erased INTEGER NOT NULL DEFAULT 0 CHECK(erased IN (0,1)),
  CHECK((erased=0 AND request_key IS NOT NULL AND fingerprint IS NOT NULL) OR (erased=0 AND request_key IS NULL AND fingerprint IS NULL) OR (erased=1 AND fingerprint IS NULL)),
  CHECK((writer_mode='host' AND host_generation IS NOT NULL) OR (writer_mode='direct' AND host_generation IS NULL))
) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX operations_caller_key ON operations(scope_key,actor_id,request_key) WHERE request_key IS NOT NULL;
CREATE TABLE operation_events(
  operation_id BLOB NOT NULL REFERENCES operations(operation_id),
  ordinal INTEGER NOT NULL CHECK(ordinal>=0),
  event_seq INTEGER NOT NULL REFERENCES events(seq),
  newly_appended INTEGER NOT NULL CHECK(newly_appended IN (0,1)),
  PRIMARY KEY(operation_id,ordinal)
) STRICT, WITHOUT ROWID;
CREATE INDEX operation_events_event ON operation_events(event_seq,operation_id);
CREATE TABLE payloads(
  payload_id INTEGER PRIMARY KEY,
  event_seq INTEGER NOT NULL REFERENCES events(seq),
  field TEXT NOT NULL,
  encoding TEXT NOT NULL CHECK(encoding IN ('utf8','bytes')),
  content BLOB NOT NULL,
  sha256 BLOB NOT NULL CHECK(length(sha256)=32),
  UNIQUE(event_seq,field)
) STRICT;
CREATE TABLE aux_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  facts TEXT NOT NULL CHECK(json_valid(facts))
) STRICT;
CREATE TABLE message_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  message_id BLOB NOT NULL CHECK(length(message_id)=16),
  recipient_id BLOB NOT NULL CHECK(length(recipient_id)=16),
  message_kind TEXT NOT NULL,
  body_payload INTEGER UNIQUE REFERENCES payloads(payload_id),
  refs TEXT NOT NULL CHECK(json_valid(refs)),
  reply_to BLOB CHECK(reply_to IS NULL OR length(reply_to)=16)
) STRICT;
CREATE TABLE mark_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  message_seq INTEGER NOT NULL REFERENCES message_data(event_seq),
  recipient_id BLOB NOT NULL CHECK(length(recipient_id)=16),
  disposition TEXT NOT NULL CHECK(disposition IN ('delivered','read','dismissed')),
  evidence_event BLOB CHECK(evidence_event IS NULL OR length(evidence_event)=16)
) STRICT;
CREATE TABLE decision_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  decision_id BLOB NOT NULL CHECK(length(decision_id)=16),
  project_id BLOB NOT NULL CHECK(length(project_id)=16),
  decision_key TEXT,
  state TEXT NOT NULL CHECK(state IN ('proposed','ratified','rejected','retracted','superseded')),
  statement_payload INTEGER REFERENCES payloads(payload_id),
  rationale_payload INTEGER REFERENCES payloads(payload_id),
  reason_payload INTEGER REFERENCES payloads(payload_id),
  expected_revision INTEGER CHECK(expected_revision IS NULL OR expected_revision>0),
  prior_proposal_id BLOB CHECK(prior_proposal_id IS NULL OR length(prior_proposal_id)=16),
  decision_kind TEXT CHECK(decision_kind IN ('note','decision')),
  replacement_id BLOB CHECK(replacement_id IS NULL OR length(replacement_id)=16),
  replacement_expected_revision INTEGER CHECK(replacement_expected_revision IS NULL OR replacement_expected_revision>0)
) STRICT;
CREATE INDEX decision_data_key ON decision_data(project_id,decision_key,event_seq DESC) WHERE decision_key IS NOT NULL;
CREATE TABLE session_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  session_id BLOB NOT NULL CHECK(length(session_id)=16),
  agent_id BLOB NOT NULL CHECK(length(agent_id)=16),
  provider TEXT NOT NULL CHECK(provider IN ('claude','codex','secode')),
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
CREATE TABLE turn_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  turn_id BLOB NOT NULL CHECK(length(turn_id)=16),
  project_id BLOB NOT NULL CHECK(length(project_id)=16),
  agent_id BLOB NOT NULL CHECK(length(agent_id)=16),
  session_id BLOB NOT NULL CHECK(length(session_id)=16),
  provider TEXT NOT NULL CHECK(provider IN ('claude','codex','secode')),
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
CREATE INDEX turn_data_agent_seq ON turn_data(project_id,agent_id,event_seq);
CREATE INDEX turn_data_session_seq ON turn_data(project_id,session_id,event_seq);
CREATE UNIQUE INDEX turn_data_id ON turn_data(project_id,turn_id);
CREATE UNIQUE INDEX capture_source_natural ON aux_data(json_extract(facts,'$.project'),json_extract(facts,'$.source'),json_extract(facts,'$.incarnation'),json_extract(facts,'$.session'),json_extract(facts,'$.consent'),json_extract(facts,'$.native_ref')) WHERE json_extract(facts,'$.capture_kind')='source';
CREATE UNIQUE INDEX capture_progress_natural ON aux_data(json_extract(facts,'$.project'),json_extract(facts,'$.source'),json_extract(facts,'$.incarnation'),json_extract(facts,'$.old_offset'),json_extract(facts,'$.new_offset'),json_extract(facts,'$.last_turn')) WHERE json_extract(facts,'$.capture_kind')='progress';
CREATE TABLE process_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  process_id BLOB NOT NULL CHECK(length(process_id)=16),
  principal_id BLOB NOT NULL CHECK(length(principal_id)=16),
  target_session_id BLOB CHECK(target_session_id IS NULL OR length(target_session_id)=16),
  root_identity TEXT NOT NULL CHECK(root_identity IN ('no-child-created','unpublished','identified','unknown')),
  identity_state TEXT NOT NULL CHECK(identity_state IN ('present','absent','unreadable')),
  identity_cause TEXT,
  machine_id INTEGER REFERENCES symbols(id),
  boot_identity INTEGER REFERENCES symbols(id),
  pid INTEGER CHECK(pid>0),
  birth_identity BLOB,
  executable INTEGER REFERENCES symbols(id),
  argv_sha256 BLOB CHECK(length(argv_sha256)=32),
  custody_version INTEGER NOT NULL CHECK(custody_version=1),
  custody BLOB NOT NULL,
  containment TEXT NOT NULL CHECK(containment IN ('cgroup','job','process-group','uncontained','unknown','not-launched')),
  containment_cause TEXT,
  containment_unknown_reason TEXT,
  containment_observed_at_us INTEGER,
  containment_probe BLOB CHECK(containment_probe IS NULL OR length(containment_probe)=16),
  state TEXT NOT NULL CHECK(state IN ('reserved','starting','running','leader-exited','stop-requested','stop-unproved','exited','lost','historical')),
  expected_revision INTEGER CHECK(expected_revision IS NULL OR expected_revision>0),
  observation_event BLOB CHECK(observation_event IS NULL OR length(observation_event)=16),
  CHECK((identity_state='present' AND machine_id IS NOT NULL AND boot_identity IS NOT NULL AND pid IS NOT NULL AND birth_identity IS NOT NULL AND executable IS NOT NULL AND argv_sha256 IS NOT NULL AND identity_cause IS NULL)
     OR (identity_state IN ('absent','unreadable') AND machine_id IS NULL AND boot_identity IS NULL AND pid IS NULL AND birth_identity IS NULL AND executable IS NULL AND argv_sha256 IS NULL AND identity_cause IS NOT NULL)),
  CHECK((root_identity='identified' AND identity_state='present')
     OR (root_identity IN ('no-child-created','unpublished') AND identity_state='absent')
     OR (root_identity='unknown' AND identity_state IN ('absent','unreadable') AND state IN ('historical','lost'))),
  CHECK(state<>'reserved' OR root_identity='no-child-created'),
  CHECK(state NOT IN ('running','leader-exited') OR root_identity='identified'),
  CHECK(state NOT IN ('stop-requested','stop-unproved','exited') OR (root_identity<>'unknown' AND observation_event IS NOT NULL)),
  CHECK((containment='uncontained' AND containment_cause IN ('no-user-manager','no-delegation','cgroup-v2-absent','cgroup-unreadable','scope-create-failed') AND containment_cause IS NOT NULL AND containment_observed_at_us IS NOT NULL AND containment_unknown_reason IS NULL)
     OR (containment IN ('cgroup','job','process-group') AND containment_cause IS NULL AND containment_observed_at_us IS NOT NULL AND containment_unknown_reason IS NULL)
     OR (containment='unknown' AND containment_cause IS NULL AND containment_unknown_reason IS NOT NULL)
     OR (containment='not-launched' AND containment_cause IS NULL AND containment_unknown_reason IS NULL))
) STRICT;
CREATE TABLE working_state_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  agent_id BLOB NOT NULL CHECK(length(agent_id)=16),
  text_payload INTEGER UNIQUE REFERENCES payloads(payload_id),
  expected_revision INTEGER CHECK(expected_revision IS NULL OR expected_revision>0)
) STRICT;
CREATE TABLE cursor_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  cursor_id BLOB NOT NULL CHECK(length(cursor_id)=16),
  agent_id BLOB NOT NULL CHECK(length(agent_id)=16),
  purpose TEXT NOT NULL,
  value BLOB NOT NULL,
  expected_revision INTEGER CHECK(expected_revision IS NULL OR expected_revision>0),
  from_seq INTEGER NOT NULL CHECK(from_seq>=0),
  to_seq INTEGER NOT NULL CHECK(to_seq>=from_seq),
  returned INTEGER NOT NULL CHECK(returned>=0),
  complete INTEGER NOT NULL CHECK(complete IN (0,1)),
  omitted INTEGER CHECK(omitted>=0),
  acknowledged_event BLOB CHECK(acknowledged_event IS NULL OR length(acknowledged_event)=16)
) STRICT;

CREATE TABLE projects(
  project_id BLOB PRIMARY KEY CHECK(length(project_id)=16),
  first_seq INTEGER NOT NULL REFERENCES events(seq),
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  state TEXT NOT NULL CHECK(state IN ('active','removed'))
) STRICT, WITHOUT ROWID;
CREATE TABLE roots(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  canonical_key BLOB NOT NULL UNIQUE,
  encoded_path INTEGER NOT NULL REFERENCES symbols(id),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(project_id,canonical_key)
) STRICT, WITHOUT ROWID;
CREATE TABLE owners(
  human_id BLOB PRIMARY KEY CHECK(length(human_id)=16),
  display_name TEXT NOT NULL,
  first_seq INTEGER NOT NULL REFERENCES events(seq),
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES events(seq)
) STRICT, WITHOUT ROWID;
CREATE TABLE principals(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  principal_id BLOB NOT NULL CHECK(length(principal_id)=16),
  principal_kind TEXT NOT NULL CHECK(principal_kind IN ('human','agent')),
  owner_id BLOB NOT NULL REFERENCES owners(human_id),
  created_by BLOB CHECK(created_by IS NULL OR length(created_by)=16),
  display_name TEXT NOT NULL COLLATE NOCASE,
  first_seq INTEGER NOT NULL REFERENCES events(seq),
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(project_id,principal_id),
  UNIQUE(project_id,display_name),
  FOREIGN KEY(project_id,created_by) REFERENCES principals(project_id,principal_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE aliases(
  project_id BLOB NOT NULL,
  alias TEXT NOT NULL,
  principal_id BLOB NOT NULL,
  imported_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(project_id,alias),
  FOREIGN KEY(project_id,principal_id) REFERENCES principals(project_id,principal_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE profiles(
  project_id BLOB NOT NULL,
  agent_id BLOB NOT NULL,
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(project_id,agent_id),
  FOREIGN KEY(project_id,agent_id) REFERENCES principals(project_id,principal_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE grants(
  scope_key BLOB NOT NULL,
  principal_id BLOB NOT NULL CHECK(length(principal_id)=16),
  grant_key TEXT NOT NULL,
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  active INTEGER NOT NULL CHECK(active IN (0,1)),
  PRIMARY KEY(scope_key,principal_id,grant_key)
) STRICT, WITHOUT ROWID;
CREATE TABLE sessions(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  session_id BLOB NOT NULL CHECK(length(session_id)=16),
  agent_id BLOB NOT NULL,
  first_seq INTEGER NOT NULL REFERENCES session_data(event_seq),
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES session_data(event_seq),
  state TEXT NOT NULL CHECK(state IN ('prepared','active','ended','revoked')),
  PRIMARY KEY(project_id,session_id),
  FOREIGN KEY(project_id,agent_id) REFERENCES principals(project_id,principal_id)
) STRICT, WITHOUT ROWID;
CREATE UNIQUE INDEX sessions_one_active ON sessions(project_id,agent_id) WHERE state='active';
CREATE INDEX sessions_agent_order ON sessions(project_id,agent_id,first_seq);
CREATE TABLE credentials(
  credential_id BLOB PRIMARY KEY CHECK(length(credential_id)=16),
  project_id BLOB NOT NULL,
  session_id BLOB NOT NULL,
  purpose TEXT NOT NULL,
  secret_sha256 BLOB NOT NULL UNIQUE CHECK(length(secret_sha256)=32),
  expires_at_us INTEGER NOT NULL,
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  activation_deadline_us INTEGER NOT NULL,
  activated_seq INTEGER REFERENCES events(seq),
  state TEXT NOT NULL CHECK(state IN ('prepared','active','revoked')),
  CHECK((state='prepared' AND activated_seq IS NULL) OR state='revoked' OR (state='active' AND activated_seq IS NOT NULL)),
  FOREIGN KEY(project_id,session_id) REFERENCES sessions(project_id,session_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE messages(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  message_id BLOB NOT NULL CHECK(length(message_id)=16),
  sent_seq INTEGER NOT NULL UNIQUE REFERENCES message_data(event_seq),
  sender_id BLOB NOT NULL CHECK(length(sender_id)=16),
  recipient_id BLOB NOT NULL CHECK(length(recipient_id)=16),
  message_kind TEXT NOT NULL,
  superseded_by BLOB CHECK(superseded_by IS NULL OR length(superseded_by)=16),
  revision INTEGER NOT NULL CHECK(revision>0),
  PRIMARY KEY(project_id,message_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX messages_project_seq ON messages(project_id,sent_seq DESC);
CREATE INDEX messages_sender_seq ON messages(project_id,sender_id,sent_seq DESC);
CREATE INDEX messages_recipient_seq ON messages(project_id,recipient_id,sent_seq DESC);
CREATE INDEX messages_kind_seq ON messages(project_id,message_kind,sent_seq DESC);
CREATE TABLE marks(
  message_seq INTEGER PRIMARY KEY REFERENCES message_data(event_seq),
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  recipient_id BLOB NOT NULL CHECK(length(recipient_id)=16),
  delivered_seq INTEGER REFERENCES mark_data(event_seq),
  read_seq INTEGER REFERENCES mark_data(event_seq),
  dismissed_seq INTEGER REFERENCES mark_data(event_seq)
) STRICT;
CREATE INDEX marks_unread ON marks(project_id,recipient_id,message_seq DESC)
  WHERE read_seq IS NULL AND dismissed_seq IS NULL;
CREATE TABLE decisions(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  decision_id BLOB NOT NULL CHECK(length(decision_id)=16),
  proposed_seq INTEGER NOT NULL REFERENCES decision_data(event_seq),
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES decision_data(event_seq),
  state TEXT NOT NULL CHECK(state IN ('proposed','ratified','rejected','retracted','superseded')),
  PRIMARY KEY(project_id,decision_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX decisions_order ON decisions(project_id,last_seq,decision_id);
CREATE INDEX decisions_state ON decisions(project_id,state,last_seq,decision_id);
CREATE TABLE capture_sources(
  project_id BLOB NOT NULL,
  source_id BLOB NOT NULL CHECK(length(source_id)=16),
  session_id BLOB NOT NULL,
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  source_incarnation BLOB NOT NULL,
  byte_offset INTEGER NOT NULL CHECK(byte_offset>=0),
  consent TEXT NOT NULL CHECK(consent IN ('capture','suppressed')),
  suppressed_count INTEGER NOT NULL CHECK(suppressed_count>=0),
  PRIMARY KEY(project_id,source_id),
  FOREIGN KEY(project_id,session_id) REFERENCES sessions(project_id,session_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE processes(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  process_id BLOB NOT NULL CHECK(length(process_id)=16),
  first_seq INTEGER NOT NULL REFERENCES process_data(event_seq),
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES process_data(event_seq),
  ownership_released INTEGER NOT NULL DEFAULT 0 CHECK(ownership_released IN (0,1)),
  state TEXT NOT NULL CHECK(state IN ('reserved','starting','running','leader-exited','stop-requested','stop-unproved','exited','lost','historical')),
  PRIMARY KEY(project_id,process_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX processes_live ON processes(project_id,state,last_seq) WHERE ownership_released=0 AND state NOT IN ('exited','historical');
CREATE TABLE working_state(
  project_id BLOB NOT NULL,
  agent_id BLOB NOT NULL,
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES working_state_data(event_seq),
  PRIMARY KEY(project_id,agent_id),
  FOREIGN KEY(project_id,agent_id) REFERENCES principals(project_id,principal_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE cursors(
  project_id BLOB NOT NULL,
  agent_id BLOB NOT NULL,
  purpose TEXT NOT NULL,
  cursor_id BLOB NOT NULL CHECK(length(cursor_id)=16),
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES cursor_data(event_seq),
  acknowledged_seq INTEGER REFERENCES cursor_data(event_seq),
  PRIMARY KEY(project_id,agent_id,purpose),
  FOREIGN KEY(project_id,agent_id) REFERENCES principals(project_id,principal_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE effects(
  effect_id BLOB PRIMARY KEY CHECK(length(effect_id)=16),
  project_id BLOB,
  kind TEXT NOT NULL,
  principal_id BLOB CHECK(principal_id IS NULL OR length(principal_id)=16),
  requested_seq INTEGER NOT NULL REFERENCES events(seq),
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  state TEXT NOT NULL CHECK(state IN ('pending','offered','witnessed','failed','abandoned')),
  FOREIGN KEY(project_id) REFERENCES projects(project_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX effects_pending ON effects(project_id,requested_seq) WHERE state IN ('pending','offered');
CREATE INDEX effects_principal_pending ON effects(project_id,principal_id,requested_seq) WHERE state IN ('pending','offered');
CREATE TABLE integrations(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  integration_id BLOB NOT NULL CHECK(length(integration_id)=16),
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  state TEXT NOT NULL CHECK(state IN ('installed','removed','conflict')),
  PRIMARY KEY(project_id,integration_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE import_runs(
  import_id BLOB PRIMARY KEY CHECK(length(import_id)=16),
  first_seq INTEGER NOT NULL REFERENCES events(seq),
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  state TEXT NOT NULL CHECK(state IN ('running','complete','partial'))
) STRICT, WITHOUT ROWID;
CREATE TABLE import_progress(
  import_id BLOB NOT NULL REFERENCES import_runs(import_id),
  family TEXT NOT NULL,
  source_key BLOB NOT NULL,
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  byte_offset INTEGER NOT NULL CHECK(byte_offset>=0),
  row_offset INTEGER NOT NULL CHECK(row_offset>=0),
  prefix_sha256 BLOB NOT NULL CHECK(length(prefix_sha256)=32),
  PRIMARY KEY(import_id,family,source_key)
) STRICT, WITHOUT ROWID;
CREATE TABLE legacy_ids(
  import_id BLOB NOT NULL REFERENCES import_runs(import_id),
  family TEXT NOT NULL,
  legacy_id TEXT NOT NULL,
  typed_id BLOB NOT NULL CHECK(length(typed_id)=16),
  imported_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(import_id,family,legacy_id)
) STRICT, WITHOUT ROWID;
-- Mutable lists read current heads with live keysets, not temporal versions.
CREATE INDEX projects_order ON projects(first_seq,project_id);
CREATE INDEX principals_order ON principals(project_id,first_seq,principal_id);
CREATE INDEX sessions_order ON sessions(project_id,first_seq,session_id);
CREATE INDEX processes_order ON processes(project_id,first_seq,process_id);
CREATE INDEX effects_order ON effects(project_id,requested_seq,effect_id);
CREATE INDEX effects_state_order ON effects(project_id,state,requested_seq,effect_id);
CREATE INDEX integrations_order ON integrations(project_id,last_seq,integration_id);
CREATE TABLE erasures(
  erasure_id BLOB PRIMARY KEY CHECK(length(erasure_id)=16),
  requested_seq INTEGER NOT NULL REFERENCES events(seq),
  completed_seq INTEGER REFERENCES events(seq),
  manifest_payload INTEGER NOT NULL REFERENCES payloads(payload_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE erased_fields(
  event_seq INTEGER NOT NULL REFERENCES events(seq),
  field TEXT NOT NULL,
  original_bytes INTEGER NOT NULL CHECK(original_bytes>=0),
  erasure_id BLOB NOT NULL REFERENCES erasures(erasure_id),
  PRIMARY KEY(event_seq,field)
) STRICT, WITHOUT ROWID;
CREATE TABLE resume_heads(
  project_id BLOB NOT NULL,
  principal_id BLOB NOT NULL,
  last_turn_seq INTEGER REFERENCES events(seq),
  last_working_state_seq INTEGER REFERENCES events(seq),
  last_cursor_seq INTEGER REFERENCES events(seq),
  last_session_seq INTEGER REFERENCES events(seq),
  unread_count INTEGER NOT NULL CHECK(unread_count>=0),
  pending_effect_count INTEGER NOT NULL CHECK(pending_effect_count>=0),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(project_id,principal_id),
  FOREIGN KEY(project_id,principal_id) REFERENCES principals(project_id,principal_id)
) STRICT, WITHOUT ROWID;


CREATE TRIGGER operations_no_update BEFORE UPDATE ON operations
WHEN NOT (NEW.operation_id=OLD.operation_id AND NEW.scope_key=OLD.scope_key AND NEW.actor_id=OLD.actor_id
  AND NEW.request_key IS OLD.request_key AND NEW.fingerprint_codec=OLD.fingerprint_codec AND NEW.recorded_incarnation=OLD.recorded_incarnation
  AND NEW.writer_mode=OLD.writer_mode AND NEW.host_generation IS OLD.host_generation AND NEW.durability=OLD.durability
  AND OLD.erased=0 AND NEW.erased=1 AND NEW.fingerprint IS NULL
  AND se_erase_operation_allowed(OLD.operation_id)=1)
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER operations_no_delete BEFORE DELETE ON operations
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER operation_events_no_update BEFORE UPDATE ON operation_events
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER operation_events_no_delete BEFORE DELETE ON operation_events
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER payloads_no_update BEFORE UPDATE ON payloads
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER payloads_no_delete BEFORE DELETE ON payloads
WHEN se_erase_body_allowed(OLD.event_seq,OLD.field)!=1
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER aux_data_no_update BEFORE UPDATE ON aux_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER aux_data_no_delete BEFORE DELETE ON aux_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER message_data_no_update BEFORE UPDATE ON message_data
WHEN NOT (NEW.event_seq=OLD.event_seq AND NEW.message_id=OLD.message_id AND NEW.recipient_id=OLD.recipient_id
  AND NEW.message_kind=OLD.message_kind AND NEW.refs=OLD.refs AND NEW.reply_to IS OLD.reply_to
  AND OLD.body_payload IS NOT NULL AND NEW.body_payload IS NULL AND se_erase_body_allowed(OLD.event_seq,'body')=1)
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER message_data_no_delete BEFORE DELETE ON message_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER mark_data_no_update BEFORE UPDATE ON mark_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER mark_data_no_delete BEFORE DELETE ON mark_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER decision_data_no_update BEFORE UPDATE ON decision_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER decision_data_no_delete BEFORE DELETE ON decision_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
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
CREATE TRIGGER process_data_no_update BEFORE UPDATE ON process_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER process_data_no_delete BEFORE DELETE ON process_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER working_state_data_no_update BEFORE UPDATE ON working_state_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER working_state_data_no_delete BEFORE DELETE ON working_state_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER cursor_data_no_update BEFORE UPDATE ON cursor_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER cursor_data_no_delete BEFORE DELETE ON cursor_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER symbols_no_update BEFORE UPDATE ON symbols
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER symbols_no_delete BEFORE DELETE ON symbols
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER identities_no_update BEFORE UPDATE ON identities
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER identities_no_delete BEFORE DELETE ON identities
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
