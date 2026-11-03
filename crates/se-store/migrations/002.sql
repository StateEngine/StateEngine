-- Schema 2 is additive and index-only: no data or query result changes, so a
-- schema-1 store stays readable while its sole host upgrades it.
CREATE INDEX cursor_data_cursor ON cursor_data(cursor_id);
CREATE INDEX process_data_principal ON process_data(principal_id,event_seq);
CREATE INDEX effect_offer_attempt ON aux_data(json_extract(facts,'$.effect'),json_extract(facts,'$.attempt')) WHERE json_extract(facts,'$.attempt') IS NOT NULL;
-- Startup cleanup begins at live sessions and resolves only their exact
-- terminal process heads, including a crash before final capture/session end.
CREATE INDEX sessions_cleanup ON sessions(project_id,session_id) WHERE state IN ('prepared','active');
CREATE INDEX process_data_session ON process_data(target_session_id,event_seq) WHERE target_session_id IS NOT NULL;
PRAGMA user_version=2;
