CREATE TABLE IF NOT EXISTS system_logs (
  id         TEXT PRIMARY KEY,
  action     TEXT NOT NULL,
  target_id  TEXT NOT NULL,
  admin_id   TEXT NOT NULL,
  details    TEXT,
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_system_logs_created_at ON system_logs(created_at);
