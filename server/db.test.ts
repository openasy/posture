import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { openDb } from "./db.ts";

describe("openDb", () => {
  it("uses WAL and migrates once", () => {
    const path = join(mkdtempSync(join(tmpdir(), "posture-")), "nested", "posture.db");
    const first = openDb(path);
    expect(first.prepare("PRAGMA journal_mode").get()).toEqual({ journal_mode: "wal" });
    first.close();

    const second = openDb(path);
    expect(second.prepare("SELECT COUNT(*) AS n FROM schema_migrations").get()).toEqual({ n: 1 });
    second.close();
  });

  it("deletes a target's reports and findings with it", () => {
    const db = openDb(":memory:");
    db.exec(`INSERT INTO targets VALUES ('t', 'prod', 'kubernetes', NULL, 'high', 'now');
      INSERT INTO scans VALUES ('s', 't', 'trivy', 'Trivy', 1, NULL, NULL, NULL, 1, 0, 0, 0, 0, 'high', 'now');
      INSERT INTO findings (target_id, fingerprint, engine, rule_id, severity, resource, message, first_seen, last_seen) VALUES ('t', 'f', 'trivy', 'x', 'low', 'r', 'm', 'now', 'now');
      DELETE FROM targets`);
    expect(db.prepare("SELECT (SELECT COUNT(*) FROM scans) + (SELECT COUNT(*) FROM findings) AS n").get()).toEqual({ n: 0 });
  });
});
