-- Notification intent belongs to the immutable message; outcomes are independent
-- for every addressed recipient. Old rows have no measured wake observation.
ALTER TABLE message_data ADD COLUMN quiet INTEGER NOT NULL DEFAULT 0 CHECK(quiet IN (0,1));
ALTER TABLE message_deliveries ADD COLUMN quiet INTEGER NOT NULL DEFAULT 0 CHECK(quiet IN (0,1));
ALTER TABLE message_deliveries ADD COLUMN wake_state TEXT NOT NULL DEFAULT 'unmeasured'
  CHECK(wake_state IN ('quiet','pending','reserved','offered','held','failed','unknown','unmeasured','not-applicable'));
ALTER TABLE message_deliveries ADD COLUMN wake_event_seq INTEGER REFERENCES events(seq);
ALTER TABLE message_deliveries ADD COLUMN wake_code TEXT;
CREATE INDEX mail_notification_pending ON message_deliveries(project_id,recipient_id,sent_seq)
  WHERE quiet=0 AND delivered_seq IS NULL AND read_seq IS NULL AND dismissed_seq IS NULL;
PRAGMA user_version=4;
