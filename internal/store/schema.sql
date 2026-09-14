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
