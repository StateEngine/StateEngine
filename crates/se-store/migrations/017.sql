-- One provider process can serve several agents on one login. Its identity stays
-- the ordinary process record; this table owns the scope's lifetime and points
-- at that process, so custody keeps one description of a native process.
CREATE TABLE shared_scope(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  scope_id BLOB NOT NULL,
  login TEXT NOT NULL CHECK(length(login)<=4096),
  server_process BLOB NOT NULL,
  phase TEXT NOT NULL CHECK(phase IN ('starting','live','stopped','died')),
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(project_id,scope_id),
  FOREIGN KEY(project_id,server_process) REFERENCES processes(project_id,process_id)
) STRICT;

-- Membership answers "is another agent still on this daemon" from the store
-- rather than from a live census. A row exists while the agent's thread is
-- attached; detaching closes it with the reason that ended it.
CREATE TABLE shared_scope_thread(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  scope_id BLOB NOT NULL,
  session_id BLOB NOT NULL,
  thread_id TEXT NOT NULL CHECK(length(thread_id)<=512),
  detached_seq INTEGER REFERENCES events(seq),
  detached_reason TEXT CHECK(detached_reason IS NULL OR length(detached_reason)<=1024),
  attached_seq INTEGER NOT NULL REFERENCES events(seq),
  revision INTEGER NOT NULL CHECK(revision>0),
  PRIMARY KEY(project_id,scope_id,session_id),
  FOREIGN KEY(project_id,scope_id) REFERENCES shared_scope(project_id,scope_id),
  FOREIGN KEY(project_id,session_id) REFERENCES sessions(project_id,session_id)
) STRICT;

CREATE INDEX shared_scope_thread_open ON shared_scope_thread(project_id,scope_id,detached_seq);
PRAGMA user_version=17;
