-- Launch consent is explicit and does not broaden legacy machine-grant verbs.
CREATE TABLE remote_launch_permissions(
  grant_id BLOB NOT NULL REFERENCES remote_grants(grant_id),
  target TEXT NOT NULL CHECK(length(target)<=4096),
  allowed INTEGER NOT NULL CHECK(allowed IN (0,1)),
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(grant_id,target)
) STRICT;
PRAGMA user_version=12;
