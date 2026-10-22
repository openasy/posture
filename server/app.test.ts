import { gzipSync } from "node:zlib";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { sarif, startApp, type TestResult } from "./test-app.ts";

let app: Awaited<ReturnType<typeof startApp>>;
beforeAll(async () => {
  app = await startApp({ version: "0.1.0" });
});
afterAll(() => app.close());

const BM = "CIS Kubernetes 1.9";
const priv: TestResult = { rule: "KSV017", level: "error", resource: "deployment/web", benchmark: BM, control: "5.2.1", section: "Pod security", message: "Container runs privileged" };
const root: TestResult = { rule: "KSV012", score: 5, resource: "deployment/web", benchmark: BM, control: "5.2.6", section: "Pod security" };
const rbac: TestResult = { rule: "KSV044", level: "error", resource: "clusterrole/admin", benchmark: BM, control: "5.1.1", section: "RBAC" };
const net: TestResult = { rule: "KSV038", score: 2, resource: "namespace/default", benchmark: BM, control: "5.3.2", section: "Network policies" };

const json = async (res: Response) => (await res.json()) as any;
const trivy = (results: TestResult[], summary?: { passed: number; failed: number; total: number }) => app.scan({ target: "prod-cluster" }, sarif("Trivy", results, summary));
const post = (path: string, body: unknown) => app.admin(path, { method: "POST", body: JSON.stringify(body) });
const target = async () => (await json(await app.admin("/api/v1/targets"))).targets[0];

describe("targets", () => {
  it("adds a target with its kind and benchmark", async () => {
    const res = await post("/api/v1/targets", { name: "prod-cluster", kind: "kubernetes", benchmark: BM });
    expect(res.status).toBe(201);
    expect(await json(res)).toMatchObject({ name: "prod-cluster", kind: "kubernetes", benchmark: BM, failOn: "high", score: null, open: { critical: 0, high: 0, medium: 0, low: 0 } });
  });

  it("refuses duplicates and what it cannot place", async () => {
    expect((await post("/api/v1/targets", { name: "prod-cluster", kind: "host" })).status).toBe(409);
    expect((await post("/api/v1/targets", { name: "x", kind: "mainframe" })).status).toBe(422);
    expect((await post("/api/v1/targets", { name: "bad name", kind: "host" })).status).toBe(422);
    expect((await post("/api/v1/targets", { name: "x", kind: "host", failOn: "urgent" })).status).toBe(422);
    expect((await post("/api/v1/targets", { name: "x", kind: "host", benchmark: "" })).status).toBe(422);
    expect((await post("/api/v1/targets", { name: "x", kind: "host", extra: 1 })).status).toBe(422);
  });
});

describe("reports", () => {
  it("adopts the first report of an engine, and scores it from the report's summary", async () => {
    const scan = await json(await trivy([priv, root, rbac], { passed: 47, failed: 3, total: 50 }));
    expect(scan).toMatchObject({ engine: "trivy", tool: "Trivy", total: 3, new: 3, blocking: 0, passed: true, score: 94, checks: { total: 50, passed: 47 }, target: { name: "prod-cluster" } });
    expect(await target()).toMatchObject({ score: 94, open: { critical: 0, high: 2, medium: 1, low: 0 } });
  });

  it("fails a later report for new failed controls at or above failOn", async () => {
    const scan = await json(await trivy([priv, root, rbac, net, { rule: "KSV001", level: "error", resource: "deployment/api", benchmark: BM, control: "5.2.2", section: "Pod security" }], { passed: 45, failed: 5, total: 50 }));
    expect(scan).toMatchObject({ total: 5, new: 2, blocking: 1, passed: false, score: 90 });
    expect(scan.findings.map((f: { rule: string }) => f.rule)).toEqual(["KSV001", "KSV038"]);
  });

  it("keeps the score of every report for the trend", async () => {
    const t = await target();
    const { points } = await json(await app.admin(`/api/v1/targets/${t.id}/history`));
    expect(points.map((p: { score: number }) => p.score)).toEqual([94, 90]);
    expect(points[0]).toMatchObject({ engine: "trivy", passed: 47, total: 50 });
    // A report without checks adds no point.
    await trivy([priv, root, rbac, net]);
    expect((await json(await app.admin(`/api/v1/targets/${t.id}/history`))).points).toHaveLength(2);
  });

  it("fixes what the engine stops reporting, and leaves other engines alone", async () => {
    await app.scan({ target: "prod-cluster", engine: "kubescape" }, sarif("kubescape", [{ rule: "C-0017", level: "error", resource: "deployment/web" }]));
    const scan = await json(await trivy([priv]));
    expect(scan).toMatchObject({ total: 1, new: 0, resolved: 3, passed: true });
    const t = await target();
    const open = (await json(await app.admin(`/api/v1/targets/${t.id}/findings`))).findings.map((f: { rule: string }) => f.rule).sort();
    expect(open).toEqual(["C-0017", "KSV017"]);
    expect((await json(await app.admin(`/api/v1/targets/${t.id}/findings?status=resolved`))).findings).toHaveLength(4);
  });

  it("counts results that name no resource, and keeps the benchmark and section filters", async () => {
    const log = JSON.parse(sarif("Trivy", [priv, root, rbac]));
    log.runs[0].results.push({ ruleId: "nowhere", message: { text: "x" }, locations: [{ physicalLocation: {} }] });
    expect(await json(await app.scan({ target: "prod-cluster" }, JSON.stringify(log)))).toMatchObject({ total: 3, ignored: 1 });
    const t = await target();
    const rules = async (query: string) => (await json(await app.admin(`/api/v1/targets/${t.id}/findings?${query}`))).findings.map((f: { rule: string }) => f.rule).sort();
    expect(await rules(`benchmark=${encodeURIComponent(BM)}&section=RBAC`)).toEqual(["KSV044"]);
    expect(await rules("section=Pod%20security")).toEqual(["KSV012", "KSV017"]);
    expect(await rules("q=5.1.1")).toEqual(["KSV044"]);
    expect(await json(await app.admin("/api/v1/facets"))).toEqual({ benchmarks: [BM], sections: ["Pod security", "RBAC"] });
  });

  it("takes a gzipped body and an engine name, and refuses what it cannot place", async () => {
    const res = await app.ingest(`/api/v1/scans?${new URLSearchParams({ target: "prod-cluster", engine: "checkov" })}`, { method: "POST", body: gzipSync(sarif("Checkov", [net])), headers: { "content-encoding": "gzip" } });
    expect(await json(res)).toMatchObject({ engine: "checkov", total: 1 });
    const problem = async (r: Response, status: number, code: string) => (expect(r.status).toBe(status), expect(await json(r)).toMatchObject({ code }));
    await problem(await app.scan({ target: "nope" }, sarif("Trivy", [])), 404, "not-found");
    await problem(await app.scan({}, sarif("Trivy", [])), 422, "invalid-body");
    await problem(await app.scan({ target: "prod-cluster", engine: "Bad Engine" }, sarif("Trivy", [])), 422, "invalid-body");
    await problem(await app.scan({ target: "prod-cluster" }, "{nope"), 422, "invalid-sarif");
    await problem(await app.scan({ target: "prod-cluster" }, JSON.stringify({ hello: 1 })), 422, "invalid-sarif");
  });
});

describe("decisions and policy", () => {
  const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();
  const decide = async (rule: string, body: unknown, status = "open") => {
    const t = await target();
    const f = (await json(await app.admin(`/api/v1/targets/${t.id}/findings?q=${rule}&status=${status}`))).findings[0];
    return app.admin(`/api/v1/targets/${t.id}/findings/${f.fingerprint}`, { method: "PUT", body: JSON.stringify(body) });
  };

  it("needs a reason, and an end for accepted risk", async () => {
    expect((await decide("KSV017", { state: "accepted", reason: "Needed by the CNI" })).status).toBe(422);
    expect((await decide("KSV017", { state: "accepted", reason: "Needed by the CNI", expiresAt: inDays(400) })).status).toBe(422);
    expect((await decide("KSV017", { state: "compensating", reason: "" })).status).toBe(422);
    expect((await decide("KSV017", { state: "ignored", reason: "x" })).status).toBe(422);
    expect((await decide("KSV017", { state: "false-positive", reason: "ok", extra: 1 })).status).toBe(422);
    const t = await target();
    expect((await app.admin(`/api/v1/targets/${t.id}/findings/nope`, { method: "PUT", body: JSON.stringify({ state: "open" }) })).status).toBe(404);
  });

  it("keeps a compensating control with the finding, so the next report does not fail for it", async () => {
    const done = await json(await decide("KSV017", { state: "compensating", reason: "Runs only on isolated nodes with a seccomp profile" }));
    expect(done).toMatchObject({ rule: "KSV017", triage: { state: "compensating", by: "admin token", expiresAt: null, active: true } });
    // The RBAC finding and the other engine's are left open.
    expect((await target()).open.high).toBe(2);
    await trivy([rbac]);
    expect(await json(await trivy([priv, rbac]))).toMatchObject({ new: 0, suppressed: 1, passed: true });
    expect(await json(await decide("KSV017", { state: "open" }, "suppressed"))).toMatchObject({ triage: null });
  });

  it("changes what fails a check", async () => {
    const t = await target();
    const patch = (body: unknown) => app.admin(`/api/v1/targets/${t.id}`, { method: "PATCH", body: JSON.stringify(body) });
    expect(await json(await patch({ failOn: "critical", benchmark: "CIS Kubernetes 1.10" }))).toMatchObject({ failOn: "critical", benchmark: "CIS Kubernetes 1.10" });
    expect(await json(await trivy([priv, rbac, { rule: "new", level: "error", resource: "x/y" }]))).toMatchObject({ new: 1, blocking: 0, passed: true });
    expect((await patch({})).status).toBe(422);
    expect((await patch({ failOn: "urgent" })).status).toBe(422);
    expect((await patch({ kind: "host" })).status).toBe(422);
    expect((await patch({ benchmark: null })).status).toBe(200);
  });

  it("filters and pages findings", async () => {
    const all = await json(await app.admin("/api/v1/findings?limit=1"));
    expect(all.findings).toHaveLength(1);
    expect(all.nextCursor).toBeDefined();
    expect((await json(await app.admin(`/api/v1/findings?limit=1&cursor=${all.nextCursor}`))).findings.length).toBe(1);
    expect((await app.admin("/api/v1/findings?severity=urgent")).status).toBe(422);
    expect((await app.admin("/api/v1/findings?status=gone")).status).toBe(422);
    expect((await app.admin("/api/v1/findings?limit=0")).status).toBe(422);
  });

  it("deletes a target with its reports and findings", async () => {
    const t = await target();
    const scans = (await json(await app.admin(`/api/v1/targets/${t.id}/scans`))).scans;
    expect(scans.length).toBeGreaterThan(3);
    expect((await app.admin(`/api/v1/scans/${scans[0].id}`)).status).toBe(200);
    expect((await app.admin(`/api/v1/targets/${t.id}`, { method: "DELETE" })).status).toBe(204);
    expect((await app.admin(`/api/v1/targets/${t.id}`)).status).toBe(404);
    expect((await json(await app.admin("/api/v1/findings"))).findings).toEqual([]);
  });
});

describe("access", () => {
  it("asks for the ingest token or an editor, and keeps targets to admins", async () => {
    const anon = (path: string, init: RequestInit = {}) => fetch(app.base + path, init);
    expect((await anon("/api/v1/scans?target=a", { method: "POST", body: "{}" })).status).toBe(401);
    expect((await anon("/api/v1/targets")).status).toBe(401);
    expect((await app.ingest("/api/v1/targets")).status).toBe(401);
    expect((await app.ingest("/api/v1/targets", { method: "POST", body: "{}" })).status).toBe(401);
    const closed = await startApp({ version: "0.1.0", ingestToken: undefined, adminToken: undefined });
    expect((await fetch(`${closed.base}/api/v1/scans?target=a`, { method: "POST", body: "{}" })).status).toBe(503);
    await closed.close();
  });

  it("answers version, health and metrics with a score per target", async () => {
    await post("/api/v1/targets", { name: "aws-prod", kind: "cloud", benchmark: "CIS AWS 3.0" });
    await app.scan({ target: "aws-prod" }, sarif("Prowler", [], { passed: 9, failed: 1, total: 10 }));
    expect(await json(await fetch(`${app.base}/api/v1/version`))).toEqual({ product: "posture", version: "0.1.0" });
    expect((await fetch(`${app.base}/healthz`)).status).toBe(200);
    const metrics = await (await fetch(`${app.base}/metrics`)).text();
    expect(metrics).toContain('openasy_build_info{product="posture",version="0.1.0"} 1');
    expect(metrics).toContain('openasy_posture_score{target="aws-prod"} 90');
    expect(metrics).toMatch(/openasy_posture_targets \d+/);
    expect(await json(await app.admin("/api/v1/summary"))).toMatchObject({ targets: 1, averageScore: 90 });
  });
});
