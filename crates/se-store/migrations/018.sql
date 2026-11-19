-- A login's shared daemon belongs to the host itself, not to a person or an
-- agent. The principal registry stays limited to humans and agents, so the
-- immutable process fact carries the host binding directly: the exact scope it
-- serves and the host epoch that originated it. Both stay fixed for the
-- record's whole life; a successor host reconciles custody without rewriting
-- the origin. Human and agent rows keep their registered principal and leave
-- the host columns empty.

CREATE TABLE process_data_host(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  process_id BLOB NOT NULL CHECK(length(process_id)=16),
  principal_id BLOB CHECK(principal_id IS NULL OR length(principal_id)=16),
  host_scope BLOB CHECK(host_scope IS NULL OR length(host_scope)=16),
  host_epoch TEXT CHECK(host_epoch IS NULL OR json_valid(host_epoch)),
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
  CHECK((principal_id IS NOT NULL AND host_scope IS NULL AND host_epoch IS NULL)
     OR (principal_id IS NULL AND host_scope IS NOT NULL AND host_epoch IS NOT NULL AND target_session_id IS NULL)),
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
INSERT INTO process_data_host SELECT event_seq,process_id,principal_id,NULL,NULL,target_session_id,root_identity,identity_state,identity_cause,machine_id,boot_identity,pid,birth_identity,executable,argv_sha256,custody_version,custody,containment,containment_cause,containment_unknown_reason,containment_observed_at_us,containment_probe,state,expected_revision,observation_event FROM process_data;
DROP TABLE process_data;
ALTER TABLE process_data_host RENAME TO process_data;
CREATE INDEX process_data_principal ON process_data(principal_id,event_seq);
CREATE INDEX process_data_session ON process_data(target_session_id,event_seq) WHERE target_session_id IS NOT NULL;
CREATE TRIGGER process_data_no_update BEFORE UPDATE ON process_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
CREATE TRIGGER process_data_no_delete BEFORE DELETE ON process_data
BEGIN SELECT RAISE(ABORT,'history-immutable'); END;
PRAGMA user_version=18;
