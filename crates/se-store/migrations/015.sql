-- The rate-cap pair count seeks the pair's in-window rows by the append
-- stamp, so the stamp is stored where the pair columns live.
ALTER TABLE messages ADD COLUMN recorded_at_us INTEGER NOT NULL DEFAULT 0;
UPDATE messages SET recorded_at_us = (SELECT e.recorded_at_us FROM events e WHERE e.seq = messages.sent_seq);
CREATE INDEX messages_pair_time ON messages(project_id, sender_id, recipient_id, recorded_at_us);
PRAGMA user_version=15;
