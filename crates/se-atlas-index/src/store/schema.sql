-- Atlas v5 index store. Postings live in compact delta-varint blobs; edits
-- append to the delta tables and a single writer folds them in lazily.

CREATE TABLE meta (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 project TEXT NOT NULL, root TEXT NOT NULL, physical_root TEXT NOT NULL,
 epoch INTEGER NOT NULL, extractor_version INTEGER NOT NULL, ignore_digest BLOB,
 generation INTEGER NOT NULL DEFAULT 0, discovery_complete INTEGER NOT NULL DEFAULT 0,
 state_json TEXT NOT NULL DEFAULT '{}'
);

-- flags: binary|minified|truncated|test|generated|extract_failed|inline_tests
CREATE TABLE files (
 id INTEGER PRIMARY KEY, key BLOB(16) UNIQUE NOT NULL CHECK(length(key)=16),
 path TEXT UNIQUE NOT NULL, lang TEXT NOT NULL, size INT, mtime_ns INT, ident BLOB,
 hash BLOB(32) NOT NULL CHECK(length(hash)=32), flags INT
);

-- df counts files and changes only at compaction; readers add post_delta.
CREATE TABLE vocab (id INTEGER PRIMARY KEY, tok TEXT UNIQUE NOT NULL, compact TEXT NOT NULL, df INT NOT NULL);
CREATE INDEX vocab_compact ON vocab(compact);
-- Base postings: delta-varint (file, tf) pairs, kept apart from vocab metadata.
CREATE TABLE vocab_post (tok INTEGER PRIMARY KEY, postings BLOB NOT NULL);
-- Current tf of (tok, file) since the last compaction; tf = 0 is a tombstone.
CREATE TABLE post_delta (tok INTEGER, file INTEGER, tf INTEGER, PRIMARY KEY(tok, file)) WITHOUT ROWID;
-- Each file's sorted delta-varint (tok, tf) pairs, for an exact re-index diff.
CREATE TABLE file_tok (file INTEGER PRIMARY KEY, toks BLOB NOT NULL);
-- Identifier trigrams over vocab: delta-varint sorted vocab ids.
CREATE TABLE gram (g INTEGER PRIMARY KEY, toks BLOB) WITHOUT ROWID;
CREATE TABLE gram_delta (g INTEGER, tok INTEGER, PRIMARY KEY(g, tok)) WITHOUT ROWID;
-- Tokens of one or two characters, which have no trigram.
CREATE TABLE short (tok TEXT, vocab_id INTEGER, PRIMARY KEY(tok, vocab_id)) WITHOUT ROWID;

CREATE TABLE sym (
 id INTEGER PRIMARY KEY, key BLOB(32) UNIQUE NOT NULL CHECK(length(key)=32),
 file INT NOT NULL, parent INT, name INT NOT NULL, kind INT, line INT, end_line INT,
 accuracy INT, exported INT, sig TEXT CHECK(sig IS NULL OR length(CAST(sig AS BLOB))<=120),
 sig_hash INT, body_hash INT
);
CREATE INDEX sym_file ON sym(file, line);
CREATE INDEX sym_name ON sym(name, file);

CREATE TABLE imp (
 file INT NOT NULL, spelling TEXT NOT NULL, target_file INT, kind INT,
 reexport INT NOT NULL DEFAULT 0, PRIMARY KEY(file, spelling)
) WITHOUT ROWID;
CREATE INDEX imp_target ON imp(target_file, file) WHERE target_file IS NOT NULL;

CREATE TABLE covers (
 test_file INT NOT NULL, target_file INT NOT NULL, how INT NOT NULL,
 via_helper INT NOT NULL DEFAULT 0, PRIMARY KEY(test_file, target_file)
) WITHOUT ROWID;
CREATE INDEX covers_target ON covers(target_file, test_file);

-- History and records, kept from v4 so their joins carry over unchanged.
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
 source_event TEXT NOT NULL, body_truncated INTEGER NOT NULL DEFAULT 0 CHECK(body_truncated IN (0,1)),
 visibility TEXT NOT NULL CHECK(visibility IN ('project','restricted')),
 audience BLOB
) STRICT;
CREATE INDEX records_kind_time ON records(kind,occurred_unix_ms DESC);
CREATE INDEX records_truncated ON records(body_truncated) WHERE body_truncated=1;
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
 source_commit INTEGER REFERENCES commits(id) ON DELETE CASCADE,
 restricted_record INTEGER REFERENCES records(id) ON DELETE CASCADE,
 PRIMARY KEY(target_kind,target_key,ordinal),
 CHECK(restricted_record IS NULL OR (source_record IS NOT NULL AND source_record=restricted_record))
) STRICT;
CREATE TABLE activity (
 target_kind TEXT NOT NULL, target_key BLOB NOT NULL,
 last_touch_unix_ms INTEGER, inbound_resolved INTEGER NOT NULL CHECK(inbound_resolved>=0),
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
CREATE INDEX touches_source ON touches(source_record);
CREATE UNIQUE INDEX touches_commit ON touches(source_commit,target_kind,target_key) WHERE source_commit IS NOT NULL;

-- Virtual tables do not participate in FK cascades. The bundled FTS5 marks
-- these tables innocuous, so these triggers also run with trusted_schema=OFF.
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

