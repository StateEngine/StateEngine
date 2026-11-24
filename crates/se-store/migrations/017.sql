-- Additive ephemeral lifecycle and terminal retirement columns on principals.
ALTER TABLE principals ADD COLUMN retired_seq INTEGER REFERENCES events(seq);
ALTER TABLE principals ADD COLUMN ephemeral_one_shot INTEGER NOT NULL DEFAULT 0 CHECK(ephemeral_one_shot IN (0, 1));
ALTER TABLE principals ADD COLUMN ephemeral_ttl_seconds INTEGER CHECK(ephemeral_ttl_seconds IS NULL OR ephemeral_ttl_seconds > 0);
CREATE INDEX principals_retired ON principals(project_id, retired_seq);
PRAGMA user_version=17;
