-- Optional explicit session-table migration. The API also asks connect-pg-simple
-- to create fleet.http_sessions if missing. Run this as the schema owner if preferred.
CREATE TABLE IF NOT EXISTS fleet.http_sessions (
  sid varchar NOT NULL PRIMARY KEY,
  sess json NOT NULL,
  expire timestamp(6) NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_http_sessions_expire ON fleet.http_sessions (expire);
