-- The rate-cap pair count seeks the pair's newest rows without scanning history.
CREATE INDEX messages_pair_seq ON messages(project_id, sender_id, recipient_id, sent_seq DESC);
PRAGMA user_version=15;
