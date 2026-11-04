CREATE TABLE meta (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), project TEXT NOT NULL,
 root TEXT NOT NULL, physical_root BLOB NOT NULL CHECK(length(physical_root)=32), epoch TEXT NOT NULL,
 extractor_version TEXT NOT NULL, ignore_digest BLOB NOT NULL,
 index_generation INTEGER NOT NULL CHECK(index_generation>=0), published_generation INTEGER NOT NULL CHECK(published_generation>=0),
 observed_serial INTEGER NOT NULL CHECK(observed_serial>=0), retention_floor INTEGER NOT NULL CHECK(retention_floor>=0),
 discovery_complete INTEGER NOT NULL, coverage_json TEXT NOT NULL CHECK(length(CAST(coverage_json AS BLOB))<=4096), state_json TEXT NOT NULL CHECK(length(CAST(state_json AS BLOB))<=4096)
) STRICT;
CREATE TABLE files (
 id INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL UNIQUE CHECK(length(key)=16),
 path TEXT NOT NULL, path_key TEXT NOT NULL UNIQUE, language TEXT,
 indexed_hash BLOB CHECK(indexed_hash IS NULL OR length(indexed_hash)=32), observed_hash BLOB CHECK(observed_hash IS NULL OR length(observed_hash)=32), bytes INTEGER NOT NULL CHECK(bytes>=0),
 identity BLOB NOT NULL, coverage_json TEXT NOT NULL CHECK(length(CAST(coverage_json AS BLOB))<=4096),
 last_good_generation INTEGER, last_code_generation INTEGER NOT NULL CHECK(last_code_generation>=0),
 last_author_generation INTEGER NOT NULL CHECK(last_author_generation>=0), baseline_reset INTEGER NOT NULL
) STRICT;
CREATE TABLE names(id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT NOT NULL UNIQUE CHECK(length(CAST(text AS BLOB))<=1024)) STRICT;
CREATE TABLE symbols (
 id INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT NULL UNIQUE CHECK(length(key)=32),
 file INTEGER NOT NULL REFERENCES files(id),
 parent INTEGER REFERENCES symbols(id),
 name INTEGER NOT NULL REFERENCES names(id), kind TEXT NOT NULL,
 start_byte INTEGER NOT NULL CHECK(start_byte>=0), end_byte INTEGER NOT NULL CHECK(end_byte>=0),
 start_line INTEGER NOT NULL CHECK(start_line>=1), start_column INTEGER NOT NULL CHECK(start_column>=0),
 end_line INTEGER NOT NULL CHECK(end_line>=1), end_column INTEGER NOT NULL CHECK(end_column>=0),
 exported INTEGER NOT NULL, signature_hash BLOB CHECK(signature_hash IS NULL OR length(signature_hash)=32), body_hash BLOB CHECK(body_hash IS NULL OR length(body_hash)=32), doc_line TEXT NOT NULL CHECK(length(CAST(doc_line AS BLOB))<=160)
) STRICT;
CREATE INDEX symbols_name ON symbols(name,file,start_byte);
CREATE INDEX symbols_file ON symbols(file,start_byte,id);
CREATE TABLE refs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, file INTEGER NOT NULL REFERENCES files(id),
 enclosing INTEGER REFERENCES symbols(id) ON DELETE SET NULL,
 target INTEGER REFERENCES symbols(id) ON DELETE SET NULL,
 spelling INTEGER NOT NULL REFERENCES names(id), kind TEXT NOT NULL,
 start_byte INTEGER NOT NULL CHECK(start_byte>=0), end_byte INTEGER NOT NULL CHECK(end_byte>=0),
 start_line INTEGER NOT NULL CHECK(start_line>=1), start_column INTEGER NOT NULL CHECK(start_column>=0),
 end_line INTEGER NOT NULL CHECK(end_line>=1), end_column INTEGER NOT NULL CHECK(end_column>=0), accuracy TEXT NOT NULL
) STRICT;
CREATE INDEX refs_target ON refs(target,file,start_byte);
CREATE INDEX refs_spelling ON refs(spelling,file,start_byte);
CREATE TABLE imports (
 id INTEGER PRIMARY KEY AUTOINCREMENT, file INTEGER NOT NULL REFERENCES files(id),
 spelling TEXT NOT NULL, local_name INTEGER REFERENCES names(id),
 imported_name INTEGER REFERENCES names(id), target_file INTEGER REFERENCES files(id)
 ON DELETE SET NULL, target_symbol INTEGER REFERENCES symbols(id) ON DELETE SET NULL,
 start_byte INTEGER NOT NULL CHECK(start_byte>=0), end_byte INTEGER NOT NULL CHECK(end_byte>=0), resolution TEXT NOT NULL
) STRICT;
CREATE TABLE import_candidates (
 import_id INTEGER NOT NULL REFERENCES imports(id) ON DELETE CASCADE,
 path_key TEXT NOT NULL, PRIMARY KEY(import_id,path_key)
) STRICT;
CREATE INDEX candidates_path ON import_candidates(path_key,import_id);
CREATE VIRTUAL TABLE symbol_fts USING fts5(
 name, split_name, path, container, doc_line, content='', contentless_delete=1
);
CREATE TABLE generations (
 generation INTEGER PRIMARY KEY CHECK(generation>=0), observed_unix_ms INTEGER NOT NULL,
 event_serial INTEGER NOT NULL CHECK(event_serial>=0), batch_kind TEXT NOT NULL
) STRICT;
CREATE TABLE observed_commits (
 oid BLOB NOT NULL, generation INTEGER NOT NULL REFERENCES generations(generation),
 PRIMARY KEY(oid,generation)
) STRICT;
CREATE TABLE changes (
 generation INTEGER NOT NULL CHECK(generation>=0), ordinal INTEGER NOT NULL CHECK(ordinal>=0),
 file_key BLOB, symbol_key BLOB, path TEXT, kind TEXT NOT NULL,
 pointer_json TEXT, previous_hash BLOB CHECK(previous_hash IS NULL OR length(previous_hash)=32), current_hash BLOB CHECK(current_hash IS NULL OR length(current_hash)=32),
 dependent_count INTEGER, dependent_complete INTEGER, dependent_generation INTEGER,
 baseline_reset INTEGER NOT NULL, bulk_json TEXT,
 PRIMARY KEY(generation,ordinal)
) STRICT;
CREATE INDEX changes_file_generation ON changes(file_key,generation,ordinal);
CREATE TABLE watch_directories (
 id INTEGER PRIMARY KEY AUTOINCREMENT, descriptor INTEGER NOT NULL UNIQUE,
 path TEXT NOT NULL, identity BLOB NOT NULL
) STRICT;
CREATE TABLE active_batch (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), kind TEXT NOT NULL,
 first_serial INTEGER NOT NULL CHECK(first_serial>=0), last_serial INTEGER NOT NULL CHECK(last_serial>=0),
 distinct_files INTEGER NOT NULL CHECK(distinct_files>=0), bulk INTEGER NOT NULL, summary_json TEXT NOT NULL
) STRICT;
CREATE TABLE staged_changes (
 ordinal INTEGER PRIMARY KEY, file_key BLOB NOT NULL,
 payload_json TEXT NOT NULL
) STRICT;
CREATE TABLE authors (
 generation INTEGER NOT NULL CHECK(generation>=0), ordinal INTEGER NOT NULL CHECK(ordinal>=0),
 resolved_at_generation INTEGER NOT NULL, hint_json TEXT NOT NULL CHECK(length(CAST(hint_json AS BLOB))<=2048),
 PRIMARY KEY(generation,ordinal),
 FOREIGN KEY(generation,ordinal) REFERENCES changes(generation,ordinal) ON DELETE CASCADE
) STRICT;
CREATE INDEX authors_resolution ON authors(resolved_at_generation,generation,ordinal);

CREATE TABLE records (
 id INTEGER PRIMARY KEY AUTOINCREMENT, record_id TEXT NOT NULL UNIQUE, kind TEXT NOT NULL,
 actor TEXT, occurred_unix_ms INTEGER NOT NULL, title TEXT NOT NULL CHECK(length(CAST(title AS BLOB))<=160),
 source_event TEXT NOT NULL,
 visibility TEXT NOT NULL CHECK(visibility IN ('project','restricted')),
 audience BLOB
) STRICT;
CREATE INDEX records_kind_time ON records(kind,occurred_unix_ms DESC);
CREATE TABLE commits (
 id INTEGER PRIMARY KEY AUTOINCREMENT, oid BLOB NOT NULL UNIQUE, author_unix_ms INTEGER NOT NULL,
 author TEXT NOT NULL, subject TEXT NOT NULL, parent_oid BLOB
) STRICT;
CREATE INDEX commits_time ON commits(author_unix_ms DESC);
CREATE TABLE mentions (
 source_kind TEXT NOT NULL, source_id INTEGER NOT NULL,
 target_kind TEXT NOT NULL, target_key BLOB NOT NULL, accuracy TEXT NOT NULL,
 PRIMARY KEY(source_kind,source_id,target_kind,target_key)
) STRICT;
CREATE INDEX mentions_target ON mentions(target_kind,target_key,source_kind,source_id);
CREATE TABLE touches (
 target_kind TEXT NOT NULL, target_key BLOB NOT NULL, ordinal INTEGER NOT NULL CHECK(ordinal>=0),
 touch_kind TEXT NOT NULL, actor TEXT, at_unix_ms INTEGER NOT NULL,
 source_record INTEGER REFERENCES records(id) ON DELETE CASCADE,
 restricted_record INTEGER REFERENCES records(id) ON DELETE CASCADE,
 PRIMARY KEY(target_kind,target_key,ordinal),
 CHECK(restricted_record IS NULL OR (source_record IS NOT NULL AND source_record=restricted_record))
) STRICT;
CREATE TABLE activity (
 target_kind TEXT NOT NULL, target_key BLOB NOT NULL,
 last_touch_unix_ms INTEGER NOT NULL, inbound_resolved INTEGER NOT NULL CHECK(inbound_resolved>=0),
 PRIMARY KEY(target_kind,target_key)
) STRICT;
CREATE INDEX activity_recent ON activity(last_touch_unix_ms DESC);
CREATE TABLE record_feed (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), last_event TEXT, last_oid BLOB,
 history_bound TEXT
) STRICT;
CREATE VIRTUAL TABLE record_fts USING fts5(title, kind, content='', contentless_delete=1);
CREATE VIRTUAL TABLE record_text_fts USING fts5(body, content='', contentless_delete=1);

CREATE INDEX touches_record ON touches(restricted_record);
CREATE INDEX changes_generation ON changes(generation);
CREATE INDEX mentions_source ON mentions(source_kind,source_id);

CREATE INDEX touches_source ON touches(source_record);

-- Virtual tables do not participate in FK cascades. The bundled FTS5 marks
-- these tables innocuous, so these triggers also run with trusted_schema=OFF.
CREATE TRIGGER symbols_search_delete AFTER DELETE ON symbols BEGIN
 DELETE FROM symbol_fts WHERE rowid=old.id;
END;
CREATE TRIGGER records_search_delete AFTER DELETE ON records BEGIN
 DELETE FROM record_fts WHERE rowid=old.id;
 DELETE FROM record_text_fts WHERE rowid=old.id;
 DELETE FROM mentions WHERE source_kind='record' AND source_id=old.id;
 DELETE FROM mentions WHERE target_kind='record' AND target_key=CAST(old.record_id AS BLOB);
END;
CREATE TRIGGER commits_links_delete AFTER DELETE ON commits BEGIN
 DELETE FROM mentions WHERE source_kind='commit' AND source_id=old.id;
 DELETE FROM touches WHERE target_kind='commit' AND target_key=old.oid;
 DELETE FROM activity WHERE target_kind='commit' AND target_key=old.oid;
END;
