-- One indexed delivery per recipient, with one canonical message event/body.
-- Existing payload and marker tables remain the historical event codec.
CREATE TABLE message_deliveries(
  project_id BLOB NOT NULL REFERENCES projects(project_id),
  message_id BLOB NOT NULL CHECK(length(message_id)=16),
  sent_seq INTEGER NOT NULL REFERENCES events(seq),
  sender_id BLOB NOT NULL CHECK(length(sender_id)=16),
  recipient_id BLOB NOT NULL CHECK(length(recipient_id)=16),
  message_kind TEXT NOT NULL,
  is_floor INTEGER NOT NULL CHECK(is_floor IN (0,1)),
  revision INTEGER NOT NULL CHECK(revision>0),
  superseded_by BLOB CHECK(superseded_by IS NULL OR length(superseded_by)=16),
  delivered_seq INTEGER REFERENCES events(seq),
  read_seq INTEGER REFERENCES events(seq),
  dismissed_seq INTEGER REFERENCES events(seq),
  PRIMARY KEY(project_id,message_id,recipient_id),
  UNIQUE(sent_seq,recipient_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX mail_project_seq ON message_deliveries(project_id,sent_seq);
CREATE INDEX mail_sender_seq ON message_deliveries(project_id,sender_id,sent_seq);
CREATE INDEX mail_recipient_seq ON message_deliveries(project_id,recipient_id,sent_seq);
CREATE INDEX mail_kind_seq ON message_deliveries(project_id,message_kind,sent_seq);
CREATE INDEX mail_unread ON message_deliveries(project_id,recipient_id,sent_seq)
  WHERE read_seq IS NULL AND dismissed_seq IS NULL;
INSERT INTO message_deliveries
  SELECT d.project_id,d.message_id,d.sent_seq,d.sender_id,d.recipient_id,
    d.message_kind,0,d.revision,d.superseded_by,
    m.delivered_seq,m.read_seq,m.dismissed_seq
  FROM messages d JOIN marks m ON m.message_seq=d.sent_seq;
CREATE TABLE work_mark_data(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  message_seq INTEGER NOT NULL REFERENCES events(seq),
  message_id BLOB NOT NULL CHECK(length(message_id)=16),
  recipient_id BLOB NOT NULL CHECK(length(recipient_id)=16),
  disposition TEXT NOT NULL CHECK(disposition IN ('delivered','read','dismissed')),
  evidence_event BLOB CHECK(evidence_event IS NULL OR length(evidence_event)=16)
) STRICT;
PRAGMA user_version=3;
