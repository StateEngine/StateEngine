-- Per-store threshold for the delayed phone status. The schema default
-- is the production sixty seconds; only trusted test homes shorten it.
ALTER TABLE store_info ADD COLUMN channel_delay_us INTEGER NOT NULL DEFAULT 60000000 CHECK(channel_delay_us>0);
PRAGMA user_version=16;
