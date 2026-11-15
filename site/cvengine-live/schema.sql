-- D1 schema for cvengine.live early-access requests.
CREATE TABLE IF NOT EXISTS early_access (
  email      TEXT PRIMARY KEY,
  company    TEXT NOT NULL,
  domain     TEXT NOT NULL DEFAULT '',  -- their main domain, host name only; empty if not given
  addresses  TEXT NOT NULL,          -- lt500 | 500-3000 | gt3000 | unknown
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
