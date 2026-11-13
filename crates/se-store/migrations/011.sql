-- Launch consent is explicit and does not broaden legacy machine-grant verbs.
CREATE TABLE remote_launch_permissions(
  grant_id BLOB NOT NULL REFERENCES remote_grants(grant_id),
  target TEXT NOT NULL CHECK(length(target)<=4096),
  allowed INTEGER NOT NULL CHECK(allowed IN (0,1)),
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(grant_id,target)
) STRICT;
CREATE TABLE remote_launch_attribution(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  agent_id BLOB NOT NULL CHECK(length(agent_id)=16),
  session_id BLOB PRIMARY KEY CHECK(length(session_id)=16),
  lifecycle_id BLOB NOT NULL UNIQUE CHECK(length(lifecycle_id)=16),
  grant_id BLOB NOT NULL REFERENCES remote_grants(grant_id),
  facts TEXT NOT NULL CHECK(length(facts)<=16384),
  event_seq INTEGER NOT NULL REFERENCES events(seq)
) STRICT;
CREATE INDEX remote_launch_target ON remote_launch_attribution(grant_id,project_id,agent_id);
PRAGMA user_version=11;
