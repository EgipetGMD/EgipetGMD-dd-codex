PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY,
 username TEXT NOT NULL,
 username_lower TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL,
 password_salt TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 expires_at INTEGER NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions(user_id);
CREATE TABLE IF NOT EXISTS entries (
 id TEXT PRIMARY KEY,
 name TEXT NOT NULL,
 category TEXT NOT NULL CHECK(category IN ('races','classes','subclasses','backgrounds','creatures','items','spells','rules')),
 edition TEXT NOT NULL DEFAULT 'both' CHECK(edition IN ('2014','2024','both','any')),
 tag TEXT NOT NULL DEFAULT '',
 description TEXT NOT NULL,
 data_json TEXT NOT NULL DEFAULT '{}',
 is_homebrew INTEGER NOT NULL DEFAULT 1,
 owner_id TEXT REFERENCES users(id) ON DELETE SET NULL,
 status TEXT NOT NULL DEFAULT 'published' CHECK(status IN ('draft','pending','published','rejected')),
 created_at INTEGER NOT NULL,
 updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS entries_category_idx ON entries(category,status);
CREATE INDEX IF NOT EXISTS entries_owner_idx ON entries(owner_id);
