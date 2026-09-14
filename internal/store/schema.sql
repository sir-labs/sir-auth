-- PostgreSQL schema (converted from the former D1 migrations 0001 + 0002). Idempotent; run at startup.
CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id     TEXT PRIMARY KEY,
  client_secret TEXT NOT NULL,
  name          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt          TEXT NOT NULL DEFAULT '',
  role          TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin', 'user')),
  created_at    BIGINT NOT NULL
);

-- Self-registered accounts need admin approval. Admins are always (re)approved so
-- the pre-existing admin can never be locked out by this migration.
ALTER TABLE users ADD COLUMN IF NOT EXISTS approved BOOLEAN NOT NULL DEFAULT FALSE;
UPDATE users SET approved = TRUE WHERE role = 'admin';

CREATE TABLE IF NOT EXISTS auth_codes (
  code         TEXT PRIMARY KEY,
  client_id    TEXT NOT NULL REFERENCES oauth_clients(client_id),
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  scope        TEXT NOT NULL,
  expires_at   BIGINT NOT NULL,
  used         BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token        TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id    TEXT NOT NULL REFERENCES oauth_clients(client_id),
  scope        TEXT NOT NULL,
  expires_at   BIGINT NOT NULL,
  revoked      BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_auth_codes_client_id ON auth_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_auth_codes_user_id ON auth_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client_id ON refresh_tokens(client_id);

CREATE TABLE IF NOT EXISTS system_logs (
  id         TEXT PRIMARY KEY,
  action     TEXT NOT NULL,
  target_id  TEXT NOT NULL,
  admin_id   TEXT NOT NULL,
  details    TEXT,
  created_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_system_logs_created_at ON system_logs(created_at);

-- Cookies issued before this unix time are rejected by /session/verify
-- (log out everywhere, password change).
ALTER TABLE users ADD COLUMN IF NOT EXISTS sessions_valid_after BIGINT NOT NULL DEFAULT 0;

-- Personal access tokens (sirpat_…). Only the sha256 is stored; revoke keeps the row
-- so request_logs still join to it.
CREATE TABLE IF NOT EXISTS api_tokens (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name         TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,
  prefix       TEXT NOT NULL,
  created_at   BIGINT NOT NULL,
  expires_at   BIGINT,
  revoked_at   BIGINT,
  last_used_at BIGINT,
  last_used_ip TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id ON api_tokens(user_id);

-- One row per request on a gated route (written by /session/verify). Kept forever.
-- ponytail: single unpartitioned table; switch to monthly partitions or archive old
-- rows once it passes ~50M rows or the windowed stats queries get slow.
CREATE TABLE IF NOT EXISTS request_logs (
  id       BIGSERIAL PRIMARY KEY,
  ts       TIMESTAMPTZ NOT NULL,
  host     TEXT NOT NULL,
  method   TEXT NOT NULL,
  path     TEXT NOT NULL,
  ip       TEXT NOT NULL,
  cred     TEXT NOT NULL,
  token_id TEXT,
  user_id  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_request_logs_user_ts ON request_logs(user_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_request_logs_token_ts ON request_logs(token_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_request_logs_ts ON request_logs(ts);

-- Per-host access policy for gated routes. No row = login required. public = TRUE lets
-- /session/verify answer 200 without credentials (anonymous). Hosts whose container
-- label is proxy.auth=false never reach sir-auth and are public regardless.
CREATE TABLE IF NOT EXISTS route_policies (
  host       TEXT PRIMARY KEY,
  public     BOOLEAN NOT NULL,
  updated_at BIGINT NOT NULL,
  updated_by TEXT NOT NULL DEFAULT ''
);
