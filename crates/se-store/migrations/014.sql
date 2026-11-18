-- One project-level captain; a cleared record retains its revision and history.
CREATE TABLE project_captain(
  project_id BLOB PRIMARY KEY REFERENCES projects(project_id),
  revision INTEGER NOT NULL CHECK(revision > 0),
  last_seq INTEGER NOT NULL REFERENCES events(seq)
) STRICT, WITHOUT ROWID;
PRAGMA user_version=14;
