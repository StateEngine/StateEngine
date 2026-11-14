-- Source permissions survive machine-session renewal and provider replacement.
CREATE TABLE remote_source_permissions(
  address TEXT PRIMARY KEY CHECK(length(address)<=4096),
  allowed INTEGER NOT NULL CHECK(allowed IN (0,1)),
  revision INTEGER NOT NULL CHECK(revision>0),
  last_seq INTEGER NOT NULL REFERENCES events(seq)
) STRICT;
CREATE TABLE remote_source_contacts(
  address TEXT PRIMARY KEY CHECK(length(address)<=4096),
  first_seq INTEGER NOT NULL REFERENCES events(seq)
) STRICT;
CREATE TABLE remote_source_revocations(
  address TEXT PRIMARY KEY CHECK(length(address)<=4096),
  request_key TEXT NOT NULL CHECK(length(request_key)<=512),
  event_seq INTEGER NOT NULL REFERENCES events(seq)
) STRICT;
INSERT INTO remote_source_contacts(address,first_seq)
SELECT json_object(
  'host',json_extract(facts,'$.attribution.source.host'),
  'project',json_extract(facts,'$.attribution.source.project'),
  'agent',json_extract(facts,'$.attribution.source.agent')),
  min(event_seq)
FROM remote_message_attribution
WHERE json_type(facts,'$.attribution.source')='object'
GROUP BY json_extract(facts,'$.attribution.source.host'),
         json_extract(facts,'$.attribution.source.project'),
         json_extract(facts,'$.attribution.source.agent');
PRAGMA user_version=12;
-- The ordinary reply commit also enqueues its stable-address delivery.
CREATE TABLE remote_reply_outbox(
  event_seq INTEGER PRIMARY KEY REFERENCES events(seq),
  project_id BLOB NOT NULL CHECK(length(project_id)=16),
  message_id BLOB NOT NULL CHECK(length(message_id)=16),
  source_address TEXT NOT NULL CHECK(length(source_address)<=4096),
  sender_target TEXT NOT NULL CHECK(length(sender_target)<=4096),
  original_message_id BLOB NOT NULL CHECK(length(original_message_id)=16),
  direction TEXT NOT NULL CHECK(direction IN ('pull','push')),
  UNIQUE(project_id,message_id)
) STRICT;
CREATE INDEX remote_reply_mailbox ON remote_reply_outbox(source_address,sender_target,event_seq);
CREATE TABLE remote_reply_push_delivery(
  event_seq INTEGER PRIMARY KEY REFERENCES remote_reply_outbox(event_seq),
  peer_message_id BLOB NOT NULL CHECK(length(peer_message_id)=16),
  record_seq INTEGER NOT NULL REFERENCES events(seq)
) STRICT;
CREATE TABLE remote_mail_contacts(
  source_address TEXT NOT NULL CHECK(length(source_address)<=4096),
  peer_host TEXT NOT NULL CHECK(length(peer_host)<=256),
  target TEXT NOT NULL CHECK(length(target)<=4096),
  original_message_id BLOB NOT NULL CHECK(length(original_message_id)=16),
  principal_id BLOB NOT NULL CHECK(length(principal_id)=16),
  facts TEXT NOT NULL CHECK(length(facts)<=16384),
  event_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(source_address,peer_host,target,original_message_id)
) STRICT;
CREATE INDEX remote_mail_contacts_principal ON remote_mail_contacts(principal_id);
CREATE TABLE remote_mail_routes(
  source_address TEXT NOT NULL CHECK(length(source_address)<=4096),
  peer_host TEXT NOT NULL CHECK(length(peer_host)<=256),
  target TEXT NOT NULL CHECK(length(target)<=4096),
  principal_id BLOB NOT NULL CHECK(length(principal_id)=16),
  facts TEXT NOT NULL CHECK(length(facts)<=16384),
  event_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(source_address,peer_host,target)
) STRICT;
CREATE TABLE remote_contact_pending(
  source_address TEXT NOT NULL CHECK(length(source_address)<=4096),
  peer_host TEXT NOT NULL CHECK(length(peer_host)<=256),
  target TEXT NOT NULL CHECK(length(target)<=4096),
  request_key TEXT NOT NULL CHECK(length(request_key)<=512),
  original_grant BLOB NOT NULL CHECK(length(original_grant)=16),
  facts TEXT NOT NULL CHECK(length(facts)<=16384),
  event_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(source_address,peer_host,target,request_key,original_grant)
) STRICT;
CREATE TABLE remote_mail_catalog(
  source_address TEXT NOT NULL CHECK(length(source_address)<=4096),
  peer_host TEXT NOT NULL CHECK(length(peer_host)<=256),
  target TEXT NOT NULL CHECK(length(target)<=4096),
  first_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(source_address,peer_host,target)
) STRICT;
CREATE INDEX remote_contact_pending_page ON remote_contact_pending(source_address,event_seq);
CREATE TABLE remote_return_attribution(
  project_id BLOB NOT NULL CHECK(length(project_id)=16),
  message_id BLOB NOT NULL CHECK(length(message_id)=16),
  peer_host TEXT NOT NULL CHECK(length(peer_host)<=256),
  peer_message_id BLOB NOT NULL CHECK(length(peer_message_id)=16),
  source_address TEXT NOT NULL CHECK(length(source_address)<=4096),
  facts TEXT NOT NULL CHECK(length(facts)<=16384),
  event_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(project_id,message_id),
  UNIQUE(peer_host,peer_message_id,source_address)
) STRICT;
CREATE TABLE remote_return_cursors(
  source_address TEXT NOT NULL CHECK(length(source_address)<=4096),
  peer_host TEXT NOT NULL CHECK(length(peer_host)<=256),
  target TEXT NOT NULL CHECK(length(target)<=4096),
  grant_id BLOB NOT NULL CHECK(length(grant_id)=16),
  cursor TEXT NOT NULL CHECK(length(cursor)<=4096),
  event_seq INTEGER NOT NULL REFERENCES events(seq),
  PRIMARY KEY(source_address,peer_host,target,grant_id)
) STRICT;
