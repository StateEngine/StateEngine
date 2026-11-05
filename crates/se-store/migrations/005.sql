-- Core-private Atlas delivery progress. These are not Atlas cache tables.
CREATE TABLE atlas_resume_roots (
 project_id BLOB NOT NULL REFERENCES projects(project_id), root TEXT NOT NULL,
 epoch TEXT NOT NULL, active INTEGER NOT NULL CHECK(active IN (0,1)),
 PRIMARY KEY(project_id,root)
) STRICT;
CREATE TABLE atlas_resume_cursors (
 project_id BLOB NOT NULL, root TEXT NOT NULL, agent_id BLOB NOT NULL,
 cursor TEXT NOT NULL CHECK(length(cursor)<=4096), revision INTEGER NOT NULL CHECK(revision>0),
 fence INTEGER NOT NULL CHECK(fence>=0),
 PRIMARY KEY(project_id,root,agent_id),
 FOREIGN KEY(project_id,root) REFERENCES atlas_resume_roots(project_id,root) ON DELETE CASCADE,
 FOREIGN KEY(project_id,agent_id) REFERENCES principals(project_id,principal_id) ON DELETE CASCADE
) STRICT;
CREATE TABLE atlas_resume_deliveries (
 project_id BLOB NOT NULL, root TEXT NOT NULL, agent_id BLOB NOT NULL,
 offer BLOB NOT NULL CHECK(length(offer)=16), delivery TEXT NOT NULL UNIQUE,
 fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32), revision INTEGER NOT NULL,
 PRIMARY KEY(project_id,root,agent_id,offer),
 FOREIGN KEY(project_id,root,agent_id) REFERENCES atlas_resume_cursors(project_id,root,agent_id) ON DELETE CASCADE
) STRICT;
PRAGMA user_version=5;
