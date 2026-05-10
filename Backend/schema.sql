-- Trident Fitness Database Schema
-- Run with: wrangler d1 execute trident-fitness-db --file=schema.sql

-- ── Users Table ──
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  last_login TEXT
);

-- ── User Settings Table ──
CREATE TABLE IF NOT EXISTS user_settings (
  user_id TEXT PRIMARY KEY,
  gender TEXT DEFAULT 'female',
  age INTEGER,
  height_ft INTEGER,
  height_in INTEGER,
  weight REAL,
  goal_weight REAL,
  activity_level REAL DEFAULT 1.55,
  name TEXT,
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ── Goals Table ──
CREATE TABLE IF NOT EXISTS user_goals (
  user_id TEXT PRIMARY KEY,
  focus TEXT DEFAULT 'fat_loss',
  cal INTEGER,
  protein INTEGER,
  carbs INTEGER,
  fat INTEGER,
  tdee INTEGER,
  deficit_per_day INTEGER,
  weeks INTEGER DEFAULT 8,
  current_weight REAL,
  goal_weight REAL,
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ── Macro Logs Table ──
CREATE TABLE IF NOT EXISTS macro_logs (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  log_date TEXT NOT NULL,
  day_index INTEGER NOT NULL,
  meal TEXT NOT NULL,
  food_name TEXT NOT NULL,
  calories REAL DEFAULT 0,
  protein REAL DEFAULT 0,
  carbs REAL DEFAULT 0,
  fat REAL DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ── Progress Logs Table ──
CREATE TABLE IF NOT EXISTS progress_logs (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  log_date TEXT NOT NULL,
  weight REAL,
  body_fat REAL,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ── Progress Photos Table ──
CREATE TABLE IF NOT EXISTS progress_photos (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  photo_url TEXT NOT NULL,
  caption TEXT,
  log_date TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ── Workout State Table ──
CREATE TABLE IF NOT EXISTS workout_state (
  user_id TEXT PRIMARY KEY,
  program TEXT,
  state_json TEXT,
  updated_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ── Personal Records Table ──
CREATE TABLE IF NOT EXISTS personal_records (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  exercise TEXT NOT NULL,
  weight REAL,
  reps INTEGER,
  log_date TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ── Sessions Table (for auth tokens) ──
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  expires_at TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ── User Blobs Table (flexible JSON storage for PRs, food library, steps, sleep) ──
CREATE TABLE IF NOT EXISTS user_blobs (
  user_id TEXT NOT NULL,
  blob_key TEXT NOT NULL,
  data_json TEXT NOT NULL,
  updated_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, blob_key),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ── Indexes for performance ──
CREATE INDEX IF NOT EXISTS idx_macro_logs_user_date ON macro_logs(user_id, log_date);
CREATE INDEX IF NOT EXISTS idx_progress_logs_user ON progress_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
