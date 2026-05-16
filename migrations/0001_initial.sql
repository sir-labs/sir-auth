CREATE TABLE IF NOT EXISTS oauth_clients (
  client_id     TEXT PRIMARY KEY,
  client_secret TEXT NOT NULL,
  name          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt          TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('admin', 'user')),
  created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_codes (
  code         TEXT PRIMARY KEY,
  client_id    TEXT NOT NULL,
  user_id      TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope        TEXT NOT NULL,
  expires_at   INTEGER NOT NULL,
  used         INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id),
  FOREIGN KEY (user_id)   REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  token        TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL,
  client_id    TEXT NOT NULL,
  scope        TEXT NOT NULL,
  expires_at   INTEGER NOT NULL,
  revoked      INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY (user_id)   REFERENCES users(id),
  FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id)
);

CREATE INDEX IF NOT EXISTS idx_auth_codes_client_id ON auth_codes(client_id);
CREATE INDEX IF NOT EXISTS idx_auth_codes_user_id ON auth_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client_id ON refresh_tokens(client_id);
