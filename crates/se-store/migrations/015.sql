-- Assignments retain their project scope and revision through closure.
CREATE TABLE assignments(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  assignment_id BLOB NOT NULL REFERENCES events(event_id),
  assignee_id BLOB NOT NULL,
  state TEXT NOT NULL CHECK(state IN ('open', 'working', 'done', 'blocked', 'handed_back')),
  revision INTEGER NOT NULL CHECK(revision > 0),
  opened_seq INTEGER NOT NULL REFERENCES events(seq),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(project_id, assignment_id),
  FOREIGN KEY(project_id, assignee_id) REFERENCES principals(project_id, principal_id)
) STRICT, WITHOUT ROWID;
CREATE TABLE assignment_floor_events(
  project_id BLOB NOT NULL,
  floor_event_id BLOB NOT NULL REFERENCES events(event_id),
  assignment_id BLOB NOT NULL,
  PRIMARY KEY(project_id, floor_event_id),
  FOREIGN KEY(project_id, assignment_id) REFERENCES assignments(project_id, assignment_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX assignments_open_order ON assignments(project_id, opened_seq) WHERE state IN ('open', 'working', 'blocked');
CREATE INDEX assignments_open_assignee ON assignments(project_id, assignee_id, opened_seq) WHERE state IN ('open', 'working', 'blocked');
PRAGMA user_version=15;
