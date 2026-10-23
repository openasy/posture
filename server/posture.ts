import { randomUUID } from "node:crypto";
import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import { parseSarif, SarifError, SEVERITIES, type Finding, type Severity } from "./sarif.ts";

export type ProblemCode =
  "invalid-token" | "invalid-json" | "invalid-body" | "invalid-sarif" | "not-found" | "conflict" | "not-configured" | "payload-too-large" | "internal-error";

export class PostureError extends Error {
  readonly status: number;
  readonly code: ProblemCode;
  constructor(status: number, code: ProblemCode, detail: string) {
    super(detail);
    this.status = status;
    this.code = code;
  }
}

export type FailOn = Severity | "none";
export type Triage = "open" | "false-positive" | "accepted" | "compensating";
export type Status = "open" | "suppressed" | "resolved";
export type Kind = "cloud" | "kubernetes" | "host";

const KINDS: Kind[] = ["cloud", "kubernetes", "host"];
const FAIL_ON: FailOn[] = [...SEVERITIES, "none"];
const TRIAGE: Triage[] = ["open", "false-positive", "accepted", "compensating"];
const RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const RANK_SQL = `CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END`;

const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const ENGINE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const MAX_ACCEPT_DAYS = 366;
/** Findings in the answer to a report, for CI logs. The rest are on the target's page. */
const SCAN_FINDINGS_IN_ANSWER = 100;
/** Points of the trend one answer holds. */
const HISTORY_POINTS = 120;

const now = () => new Date().toISOString();
const bad = (detail: string) => new PostureError(422, "invalid-body", detail);
const notFound = (what: string) => new PostureError(404, "not-found", `${what} does not exist.`);

export interface Page<T> {
  items: T[];
  /** Opaque; pass it back as `cursor` for the next page. Absent on the last page (ADR 0024). */
  nextCursor?: string;
}

const encodeCursor = (offset: number) => Buffer.from(JSON.stringify({ o: offset })).toString("base64url");
function decodeCursor(cursor: string | undefined): number {
  if (!cursor) return 0;
  try {
    const o = (JSON.parse(Buffer.from(cursor, "base64url").toString("utf8")) as { o?: unknown }).o;
    if (typeof o === "number" && Number.isSafeInteger(o) && o >= 0) return o;
  } catch {
    // fall through
  }
  throw bad("cursor is not one this API returned.");
}

export function parseLimit(value: string | null, max = 500, fallback = 100): number {
  if (value === null) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n < 1 || n > max) throw bad(`limit must be between 1 and ${max}.`);
  return n;
}

export type Counts = Record<Severity, number>;
const zero = (): Counts => ({ critical: 0, high: 0, medium: 0, low: 0 });

const round1 = (n: number) => Math.round(n * 10) / 10;

export interface FindingFilter {
  status: Status;
  severity?: Severity[];
  q?: string;
  targetId?: string;
  benchmark?: string;
  section?: string;
}

interface FindingRow {
  target_id: string;
  target_name: string;
  fingerprint: string;
  engine: string;
  rule_id: string;
  severity: Severity;
  resource: string;
  benchmark: string | null;
  control: string | null;
  section: string | null;
  message: string;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
  triage: Triage;
  reason: string | null;
  triaged_by: string | null;
  triaged_at: string | null;
  expires_at: string | null;
}

export interface PostureOptions {
  /** Reports, and fixed findings nobody decided about, older than this are deleted (ADR 0015). */
  retentionDays?: number;
}

export function createPosture(db: DatabaseSync, { retentionDays = 365 }: PostureOptions = {}) {
  // A decision that has not expired. A finding whose acceptance ran out is open again.
  const SUPPRESSED = `(triage <> 'open' AND (expires_at IS NULL OR expires_at > ?))`;

  const targetRow = (id: string) => {
    const r = db.prepare("SELECT * FROM targets WHERE id = ?").get(id) as Record<string, any> | undefined;
    if (!r) throw notFound("The target");
    return r;
  };

  function openCounts(targetId?: string): Counts {
    const c = zero();
    const rows = db
      .prepare(
        `SELECT severity, COUNT(*) AS n FROM findings WHERE resolved_at IS NULL AND NOT ${SUPPRESSED} ${targetId ? "AND target_id = ?" : ""} GROUP BY severity`,
      )
      .all(...([now(), ...(targetId ? [targetId] : [])] as SQLInputValue[])) as Array<{ severity: Severity; n: number }>;
    for (const r of rows) c[r.severity] = r.n;
    return c;
  }

  /** The score of the newest report that had one. */
  const latestScore = (targetId: string) =>
    (
      db.prepare("SELECT score FROM scans WHERE target_id = ? AND score IS NOT NULL ORDER BY created_at DESC, rowid DESC LIMIT 1").get(targetId) as
        { score: number } | undefined
    )?.score ?? null;

  function presentTarget(t: Record<string, any>) {
    const last = db
      .prepare("SELECT created_at, engine, new_count, blocking FROM scans WHERE target_id = ? ORDER BY created_at DESC, rowid DESC LIMIT 1")
      .get(t.id) as Record<string, any> | undefined;
    const suppressed = (
      db.prepare(`SELECT COUNT(*) AS n FROM findings WHERE target_id = ? AND resolved_at IS NULL AND ${SUPPRESSED}`).get(t.id, now()) as { n: number }
    ).n;
    return {
      id: t.id as string,
      name: t.name as string,
      kind: t.kind as Kind,
      benchmark: (t.benchmark as string | null) ?? null,
      failOn: t.fail_on as FailOn,
      score: latestScore(t.id),
      open: openCounts(t.id),
      suppressed,
      lastScan: last ? { at: last.created_at as string, engine: last.engine as string, new: last.new_count as number, passed: last.blocking === 0 } : null,
      createdAt: t.created_at as string,
    };
  }

  function presentFinding(f: FindingRow) {
    const active = f.triage !== "open" && (!f.expires_at || f.expires_at > now());
    return {
      target: { id: f.target_id, name: f.target_name },
      fingerprint: f.fingerprint,
      engine: f.engine,
      rule: f.rule_id,
      severity: f.severity,
      resource: f.resource,
      benchmark: f.benchmark,
      control: f.control,
      section: f.section,
      message: f.message,
      firstSeen: f.first_seen,
      lastSeen: f.last_seen,
      resolvedAt: f.resolved_at,
      triage:
        f.triage === "open"
          ? null
          : { state: f.triage as Exclude<Triage, "open">, reason: f.reason!, by: f.triaged_by, at: f.triaged_at, expiresAt: f.expires_at, active },
    };
  }

  function findingsQuery(filter: FindingFilter, cursor: string | undefined, limit: number) {
    const where: string[] = [];
    const args: SQLInputValue[] = [];
    const at = `'${now()}'`;
    if (filter.status === "resolved") where.push("f.resolved_at IS NOT NULL");
    else {
      where.push("f.resolved_at IS NULL");
      where.push(filter.status === "suppressed" ? SUPPRESSED.replace("?", at) : `NOT ${SUPPRESSED.replace("?", at)}`);
    }
    if (filter.targetId) (where.push("f.target_id = ?"), args.push(filter.targetId));
    if (filter.benchmark) (where.push("f.benchmark = ?"), args.push(filter.benchmark));
    if (filter.section) (where.push("f.section = ?"), args.push(filter.section));
    if (filter.severity?.length) (where.push(`f.severity IN (${filter.severity.map(() => "?").join(",")})`), args.push(...filter.severity));
    if (filter.q) {
      const like = `%${filter.q.replace(/[\\%_]/g, "\\$&")}%`;
      where.push("(f.rule_id LIKE ? ESCAPE '\\' OR f.resource LIKE ? ESCAPE '\\' OR f.message LIKE ? ESCAPE '\\' OR f.control LIKE ? ESCAPE '\\')");
      args.push(like, like, like, like);
    }
    const offset = decodeCursor(cursor);
    const rows = db
      .prepare(
        `SELECT f.*, t.name AS target_name FROM findings f JOIN targets t ON t.id = f.target_id WHERE ${where.join(" AND ")}
         ORDER BY ${RANK_SQL.replaceAll("severity", "f.severity")} DESC, f.first_seen DESC, f.fingerprint LIMIT ? OFFSET ?`,
      )
      .all(...args, limit + 1, offset) as unknown as FindingRow[];
    return {
      items: rows.slice(0, limit).map(presentFinding),
      ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }),
    } satisfies Page<unknown>;
  }

  function presentScan(s: Record<string, any>, targetName: string) {
    return {
      id: s.id as string,
      target: { id: s.target_id as string, name: targetName },
      engine: s.engine as string,
      tool: s.tool as string,
      total: s.total as number,
      checks: s.checks_total === null ? null : { total: s.checks_total as number, passed: s.checks_passed as number },
      score: (s.score as number | null) ?? null,
      new: s.new_count as number,
      resolved: s.resolved as number,
      suppressed: s.suppressed as number,
      ignored: s.ignored as number,
      blocking: s.blocking as number,
      failOn: s.fail_on as FailOn,
      passed: s.blocking === 0,
      createdAt: s.created_at as string,
    };
  }

  const failOnOf = (value: unknown): FailOn => {
    if (typeof value !== "string" || !FAIL_ON.includes(value as FailOn)) throw bad(`failOn must be one of ${FAIL_ON.join(", ")}.`);
    return value as FailOn;
  };
  const benchmarkOf = (value: unknown): string | null => {
    if (value === null) return null;
    if (typeof value !== "string" || !value.trim() || value.length > 128) throw bad("benchmark is a label up to 128 characters, such as CIS Kubernetes 1.9.");
    return value.trim();
  };

  return {
    createTarget(body: Record<string, unknown>) {
      const { name, kind, benchmark = null, failOn = "high", ...rest } = body;
      if (Object.keys(rest).length || typeof name !== "string" || !NAME.test(name))
        throw bad("Expected { name, kind, benchmark?, failOn? }; name is up to 64 letters, digits, . _ and -.");
      if (typeof kind !== "string" || !KINDS.includes(kind as Kind)) throw bad(`kind must be one of ${KINDS.join(", ")}.`);
      if (db.prepare("SELECT 1 FROM targets WHERE name = ?").get(name)) throw new PostureError(409, "conflict", "A target with this name exists.");
      const id = randomUUID();
      db.prepare("INSERT INTO targets (id, name, kind, benchmark, fail_on, created_at) VALUES (?, ?, ?, ?, ?, ?)").run(
        id,
        name,
        kind,
        benchmarkOf(benchmark),
        failOnOf(failOn),
        now(),
      );
      return presentTarget(targetRow(id));
    },

    listTargets(cursor: string | undefined, limit: number): Page<ReturnType<typeof presentTarget>> {
      const offset = decodeCursor(cursor);
      const rows = db.prepare("SELECT * FROM targets ORDER BY name LIMIT ? OFFSET ?").all(limit + 1, offset) as Array<Record<string, any>>;
      return { items: rows.slice(0, limit).map(presentTarget), ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }) };
    },

    target: (id: string) => presentTarget(targetRow(id)),

    updateTarget(id: string, body: Record<string, unknown>) {
      targetRow(id);
      const { benchmark, failOn, ...rest } = body;
      if (Object.keys(rest).length || (benchmark === undefined && failOn === undefined)) throw bad("Expected { benchmark?, failOn? }.");
      if (benchmark !== undefined) db.prepare("UPDATE targets SET benchmark = ? WHERE id = ?").run(benchmarkOf(benchmark), id);
      if (failOn !== undefined) db.prepare("UPDATE targets SET fail_on = ? WHERE id = ?").run(failOnOf(failOn), id);
      return presentTarget(targetRow(id));
    },

    deleteTarget(id: string) {
      if (db.prepare("DELETE FROM targets WHERE id = ?").run(id).changes === 0) throw notFound("The target");
    },

    /** The score of every report that had one, oldest first, for the trend. */
    history(id: string) {
      targetRow(id);
      const rows = db
        .prepare(
          "SELECT created_at, engine, score, checks_passed, checks_total FROM scans WHERE target_id = ? AND score IS NOT NULL ORDER BY created_at DESC, rowid DESC LIMIT ?",
        )
        .all(id, HISTORY_POINTS) as Array<{ created_at: string; engine: string; score: number; checks_passed: number; checks_total: number }>;
      return { points: rows.reverse().map((r) => ({ at: r.created_at, engine: r.engine, score: r.score, passed: r.checks_passed, total: r.checks_total })) };
    },

    /**
     * Takes a SARIF report from a checker of configuration. What the same engine reported before and does not report
     * now is fixed. The first report of an engine for a target adopts what is there; later ones fail the check for new
     * failed controls at or above the target's failOn that nobody has decided about.
     */
    ingest(params: { target: string | null; engine: string | null }, raw: Buffer) {
      const name = params.target;
      if (!name || !NAME.test(name)) throw bad("target is required: the name of a target.");
      const target = db.prepare("SELECT * FROM targets WHERE name = ?").get(name) as Record<string, any> | undefined;
      if (!target) throw notFound("The target");
      if (params.engine && !ENGINE.test(params.engine)) throw bad("engine is lowercase letters, digits and -, up to 32.");

      let body: unknown;
      try {
        body = JSON.parse(raw.toString("utf8"));
      } catch {
        throw new PostureError(422, "invalid-sarif", "The body is not JSON.");
      }
      let parsed: ReturnType<typeof parseSarif>;
      try {
        parsed = parseSarif(body);
      } catch (err) {
        if (err instanceof SarifError) throw new PostureError(422, "invalid-sarif", err.message);
        throw err;
      }
      const engine = params.engine || (parsed.tool.toLowerCase().match(/[a-z0-9]+/)?.[0] ?? "other").slice(0, 32);
      const kept = parsed.findings;
      const score = parsed.checks && parsed.checks.total > 0 ? round1((parsed.checks.passed / parsed.checks.total) * 100) : null;

      const at = now();
      const id = randomUUID();
      const failOn = target.fail_on as FailOn;
      db.exec("BEGIN IMMEDIATE");
      try {
        const known = new Map<string, { resolved_at: string | null; triage: Triage; expires_at: string | null }>();
        for (const r of db
          .prepare("SELECT fingerprint, resolved_at, triage, expires_at FROM findings WHERE target_id = ? AND engine = ?")
          .all(target.id, engine) as Array<{ fingerprint: string; resolved_at: string | null; triage: Triage; expires_at: string | null }>)
          known.set(r.fingerprint, r);
        const first = !db.prepare("SELECT 1 FROM scans WHERE target_id = ? AND engine = ?").get(target.id, engine);
        const decided = (f: Finding) => {
          const k = known.get(f.fingerprint);
          return !!k && k.triage !== "open" && (!k.expires_at || k.expires_at > at);
        };
        const fresh = kept.filter((f) => !known.has(f.fingerprint) || known.get(f.fingerprint)!.resolved_at !== null);
        const added = fresh.filter((f) => !decided(f));
        const blocking = failOn === "none" || first ? 0 : added.filter((f) => RANK[f.severity] >= RANK[failOn]).length;

        const upsert = db.prepare(
          `INSERT INTO findings (target_id, fingerprint, engine, rule_id, severity, resource, benchmark, control, section, message, first_seen, last_seen)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (target_id, fingerprint) DO UPDATE SET severity = excluded.severity, benchmark = excluded.benchmark, control = excluded.control, section = excluded.section,
             message = excluded.message, last_seen = excluded.last_seen,
             first_seen = CASE WHEN findings.resolved_at IS NULL THEN findings.first_seen ELSE excluded.first_seen END, resolved_at = NULL`,
        );
        for (const f of kept)
          upsert.run(target.id, f.fingerprint, engine, f.ruleId, f.severity, f.resource, f.benchmark, f.control, f.section, f.message, at, at);
        const resolved = db
          .prepare("UPDATE findings SET resolved_at = ? WHERE target_id = ? AND engine = ? AND resolved_at IS NULL AND last_seen < ?")
          .run(at, target.id, engine, at).changes as number;

        db.prepare(
          `INSERT INTO scans (id, target_id, engine, tool, total, checks_total, checks_passed, score, new_count, resolved, suppressed, ignored, blocking, fail_on, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ).run(
          id,
          target.id,
          engine,
          parsed.tool,
          kept.length,
          parsed.checks?.total ?? null,
          parsed.checks?.passed ?? null,
          score,
          added.length,
          resolved,
          fresh.length - added.length,
          parsed.skipped,
          blocking,
          failOn,
          at,
        );
        db.exec("COMMIT");
        return {
          ...presentScan(db.prepare("SELECT * FROM scans WHERE id = ?").get(id) as Record<string, any>, name),
          findings: added
            .sort((a, b) => RANK[b.severity] - RANK[a.severity])
            .slice(0, SCAN_FINDINGS_IN_ANSWER)
            .map((f) => ({ fingerprint: f.fingerprint, rule: f.ruleId, severity: f.severity, resource: f.resource, control: f.control, message: f.message })),
        };
      } catch (err) {
        db.exec("ROLLBACK");
        throw err;
      }
    },

    /** What this product knows servers by, to say which in the hosts file it has nothing for (ADR 0052): host targets. */
    knownHosts(): string[] {
      return (db.prepare("SELECT name FROM targets WHERE kind = 'host'").all() as Array<{ name: string }>).map((r) => r.name);
    },

    summary() {
      const targets = (db.prepare("SELECT COUNT(*) AS n FROM targets").get() as { n: number }).n;
      const suppressed = (db.prepare(`SELECT COUNT(*) AS n FROM findings WHERE resolved_at IS NULL AND ${SUPPRESSED}`).get(now()) as { n: number }).n;
      const week = new Date(Date.now() - 7 * 86_400_000).toISOString();
      const failing = (db.prepare("SELECT COUNT(*) AS n FROM scans WHERE blocking > 0 AND created_at > ?").get(week) as { n: number }).n;
      const lastScanAt = (db.prepare("SELECT MAX(created_at) AS t FROM scans").get() as { t: string | null }).t;
      const scores = (db.prepare("SELECT id FROM targets").all() as Array<{ id: string }>).map((t) => latestScore(t.id)).filter((s): s is number => s !== null);
      return {
        targets,
        open: openCounts(),
        suppressed,
        failingChecks: failing,
        lastScanAt,
        averageScore: scores.length ? round1(scores.reduce((a, b) => a + b, 0) / scores.length) : null,
      };
    },

    severityTotals: () => openCounts(),
    suppressedCount: () => (db.prepare(`SELECT COUNT(*) AS n FROM findings WHERE resolved_at IS NULL AND ${SUPPRESSED}`).get(now()) as { n: number }).n,
    scores: () =>
      (db.prepare("SELECT id, name FROM targets ORDER BY name").all() as Array<{ id: string; name: string }>).map((t) => ({
        target: t.name,
        score: latestScore(t.id),
      })),

    findings(filter: FindingFilter, cursor: string | undefined, limit: number) {
      if (filter.targetId) targetRow(filter.targetId);
      return findingsQuery(filter, cursor, limit);
    },

    /** The benchmarks and sections that findings carry, for the filters. */
    facets() {
      const rows = db
        .prepare("SELECT DISTINCT benchmark, section FROM findings WHERE resolved_at IS NULL AND (benchmark IS NOT NULL OR section IS NOT NULL)")
        .all() as Array<{ benchmark: string | null; section: string | null }>;
      return {
        benchmarks: [...new Set(rows.map((r) => r.benchmark).filter((b): b is string => !!b))].sort(),
        sections: [...new Set(rows.map((r) => r.section).filter((b): b is string => !!b))].sort(),
      };
    },

    scans(targetId: string, cursor: string | undefined, limit: number) {
      const t = targetRow(targetId);
      const offset = decodeCursor(cursor);
      const rows = db
        .prepare("SELECT * FROM scans WHERE target_id = ? ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?")
        .all(targetId, limit + 1, offset) as Array<Record<string, any>>;
      return {
        items: rows.slice(0, limit).map((s) => presentScan(s, t.name)),
        ...(rows.length > limit && { nextCursor: encodeCursor(offset + limit) }),
      } satisfies Page<unknown>;
    },

    scan(id: string) {
      const s = db.prepare("SELECT s.*, t.name AS target_name FROM scans s JOIN targets t ON t.id = s.target_id WHERE s.id = ?").get(id) as
        Record<string, any> | undefined;
      if (!s) throw notFound("The scan");
      return presentScan(s, s.target_name);
    },

    /** Sets or clears the decision about one finding. It stays with the finding across reports. */
    triage(targetId: string, fingerprint: string, body: Record<string, unknown>, by: string) {
      targetRow(targetId);
      const { state, reason, expiresAt, ...rest } = body;
      if (Object.keys(rest).length || typeof state !== "string" || !TRIAGE.includes(state as Triage))
        throw bad(`Expected { state, reason?, expiresAt? }; state is one of ${TRIAGE.join(", ")}.`);
      if (!db.prepare("SELECT 1 FROM findings WHERE target_id = ? AND fingerprint = ?").get(targetId, fingerprint)) throw notFound("The finding");
      if (state === "open") {
        db.prepare(
          "UPDATE findings SET triage = 'open', reason = NULL, triaged_by = NULL, triaged_at = NULL, expires_at = NULL WHERE target_id = ? AND fingerprint = ?",
        ).run(targetId, fingerprint);
      } else {
        // A decision without a reason is lost the day its author leaves (ADR 0045).
        if (typeof reason !== "string" || reason.trim().length < 3 || reason.length > 500) throw bad("reason is required: 3 to 500 characters.");
        let expires: string | null = null;
        if (expiresAt !== undefined && expiresAt !== null) {
          const t = typeof expiresAt === "string" ? Date.parse(expiresAt) : NaN;
          if (Number.isNaN(t) || t <= Date.now()) throw bad("expiresAt must be a date in the future.");
          if (t > Date.now() + MAX_ACCEPT_DAYS * 86_400_000) throw bad(`expiresAt must be within ${MAX_ACCEPT_DAYS} days.`);
          expires = new Date(t).toISOString();
        }
        // Accepted risk always ends; a false positive or a compensating control does not need to.
        if (state === "accepted" && !expires) throw bad("expiresAt is required for accepted risk.");
        db.prepare("UPDATE findings SET triage = ?, reason = ?, triaged_by = ?, triaged_at = ?, expires_at = ? WHERE target_id = ? AND fingerprint = ?").run(
          state,
          reason.trim(),
          by,
          now(),
          expires,
          targetId,
          fingerprint,
        );
      }
      const row = db
        .prepare("SELECT f.*, t.name AS target_name FROM findings f JOIN targets t ON t.id = f.target_id WHERE f.target_id = ? AND f.fingerprint = ?")
        .get(targetId, fingerprint) as unknown as FindingRow;
      return presentFinding(row);
    },

    purge() {
      const before = new Date(Date.now() - retentionDays * 86_400_000).toISOString();
      db.prepare("DELETE FROM scans WHERE created_at < ?").run(before);
      db.prepare("DELETE FROM findings WHERE resolved_at IS NOT NULL AND resolved_at < ? AND triage = 'open'").run(before);
    },
  };
}

export type Posture = ReturnType<typeof createPosture>;
export { SEVERITIES };
