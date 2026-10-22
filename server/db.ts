import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";

// Forward-only migrations (ADR 0010): append new entries, never edit or remove old ones.
const MIGRATIONS = [
  `CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
   -- Something whose configuration is judged: a cloud account, a Kubernetes cluster or a group of hosts.
   CREATE TABLE targets (
     id TEXT PRIMARY KEY,
     name TEXT NOT NULL UNIQUE,
     kind TEXT NOT NULL CHECK (kind IN ('cloud', 'kubernetes', 'host')),
     benchmark TEXT,
     fail_on TEXT NOT NULL CHECK (fail_on IN ('critical', 'high', 'medium', 'low', 'none')),
     created_at TEXT NOT NULL
   );
   -- One row per report. checks_* come from the report's own summary or from its passed results; score is the share
   -- of checks that passed, kept for every report so the trend can be drawn.
   CREATE TABLE scans (
     id TEXT PRIMARY KEY,
     target_id TEXT NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
     engine TEXT NOT NULL,
     tool TEXT NOT NULL,
     total INTEGER NOT NULL,
     checks_total INTEGER,
     checks_passed INTEGER,
     score REAL,
     new_count INTEGER NOT NULL,
     resolved INTEGER NOT NULL,
     suppressed INTEGER NOT NULL,
     ignored INTEGER NOT NULL,
     blocking INTEGER NOT NULL,
     fail_on TEXT NOT NULL,
     created_at TEXT NOT NULL
   );
   CREATE INDEX scans_target ON scans (target_id, created_at DESC);
   -- One row per failed control on one resource of a target, found again by its fingerprint. A row an engine stops
   -- reporting gets resolved_at and opens again if the same control fails again. Decisions stay on the row.
   CREATE TABLE findings (
     target_id TEXT NOT NULL REFERENCES targets (id) ON DELETE CASCADE,
     fingerprint TEXT NOT NULL,
     engine TEXT NOT NULL,
     rule_id TEXT NOT NULL,
     severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
     resource TEXT NOT NULL,
     benchmark TEXT,
     control TEXT,
     section TEXT,
     message TEXT NOT NULL,
     first_seen TEXT NOT NULL,
     last_seen TEXT NOT NULL,
     resolved_at TEXT,
     triage TEXT NOT NULL DEFAULT 'open' CHECK (triage IN ('open', 'false-positive', 'accepted', 'compensating')),
     reason TEXT,
     triaged_by TEXT,
     triaged_at TEXT,
     expires_at TEXT,
     PRIMARY KEY (target_id, fingerprint)
   );
   CREATE INDEX findings_open ON findings (target_id, severity) WHERE resolved_at IS NULL`,
];

/** Opens the product's single SQLite file in WAL mode (ADR 0011) and migrates it forward. */
export function openDb(path: string): DatabaseSync {
  if (path !== ":memory:") mkdirSync(dirname(path), { recursive: true });
  const db = new DatabaseSync(path);
  db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;");
  db.exec("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)");
  const row = db.prepare("SELECT COALESCE(MAX(version), 0) AS v FROM schema_migrations").get() as { v: number };
  for (let v = row.v; v < MIGRATIONS.length; v++) {
    db.exec("BEGIN");
    try {
      db.exec(MIGRATIONS[v]!);
      db.prepare("INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)").run(v + 1, new Date().toISOString());
      db.exec("COMMIT");
    } catch (err) {
      db.exec("ROLLBACK");
      throw err;
    }
  }
  return db;
}
