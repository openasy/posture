import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Ajv2020 } from "ajv/dist/2020.js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ADMIN_TOKEN, INGEST_TOKEN, sarif, startApp } from "./test-app.ts";

// Contract tests (ADR 0024): every response the API sends must match openapi.json.

type Spec = {
  info: { version: string };
  paths: Record<string, Record<string, { responses: Record<string, { $ref?: string; content?: Record<string, { schema: object }> }> }>>;
  components: { responses: Record<string, { content: Record<string, { schema: object }> }> };
};

const spec = JSON.parse(readFileSync(new URL("../openapi.json", import.meta.url), "utf8")) as Spec;
const { version } = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };

const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(spec, "openapi");

const docsDir = mkdtempSync(join(tmpdir(), "posture-docs-"));
writeFileSync(join(docsDir, "index.html"), "<!doctype html><title>API</title>");

let app: Awaited<ReturnType<typeof startApp>>;
let base: string;
const covered = new Set<string>();

beforeAll(async () => {
  app = await startApp({ version, openapi: spec, docsDir });
  base = app.base;
});

afterAll(() => app.close());

/** Calls the API and checks status, content type and body against the description. */
async function call(method: string, path: string, init: RequestInit = {}, concrete = path) {
  const res = await fetch(base + concrete, { ...init, method });
  const operation = spec.paths[path]?.[method.toLowerCase()];
  expect(operation, `${method} ${path} is not in openapi.json`).toBeDefined();
  covered.add(`${method} ${path}`);

  const declared = operation!.responses[String(res.status)];
  expect(declared, `${method} ${concrete} answered ${res.status}, which openapi.json does not list`).toBeDefined();
  // A response is either inline or a $ref to components/responses; build the JSON pointer to its schema either way.
  const shared = declared!.$ref?.split("/").pop();
  const response = shared ? spec.components.responses[shared]! : declared!;
  const at = shared ? `openapi#/components/responses/${shared}` : `openapi#/paths/${path.replaceAll("/", "~1")}/${method.toLowerCase()}/responses/${res.status}`;

  if (!response.content) {
    expect(res.headers.get("content-length") ?? "0", `${method} ${path} ${res.status} should have no body`).toBe("0");
    return { res, body: undefined };
  }
  const type = res.headers.get("content-type")!.split(";")[0]!;
  expect(response.content?.[type], `${method} ${path} ${res.status} sent ${type}, which openapi.json does not list`).toBeDefined();

  const body = type.endsWith("json") ? await res.json() : await res.text();
  const schema = `${at}/content/${type.replace("/", "~1")}/schema`;
  const validate = ajv.getSchema(schema)!;
  expect(validate(body), JSON.stringify(validate.errors)).toBe(true);
  return { res, body };
}

const auth = (token: string, body?: string, type = "application/json") => ({ headers: { authorization: `Bearer ${token}`, "content-type": type }, ...(body !== undefined && { body }) });
const admin = (body?: unknown) => auth(ADMIN_TOKEN, body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body));
const inDays = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString();

describe("openapi.json", () => {
  it("has the version of this release", () => {
    expect(spec.info.version).toBe(version);
  });

  it("is served with the running version", async () => {
    const served = (await (await fetch(`${base}/api/openapi.json`)).json()) as Spec;
    expect(served.info.version).toBe(version);
    // posture's own operations, then sign-in from @openasy/auth (tested against its description in that package).
    expect(Object.keys(served.paths).filter((p) => !p.startsWith("/api/v1/auth/"))).toEqual(Object.keys(spec.paths));
    expect(served.paths["/api/v1/auth/login"]).toBeDefined();
  });

  it("serves the API reference at /api/docs/", async () => {
    expect((await fetch(`${base}/api/docs`, { redirect: "manual" })).headers.get("location")).toBe("/api/docs/");
    const res = await fetch(`${base}/api/docs/`);
    expect(res.headers.get("content-type")).toContain("text/html");
    expect((await fetch(`${base}/api/docs/../../package.json`)).status).not.toBe(200);
  });
});

describe("responses match openapi.json", () => {
  let target = "";
  let fingerprint = "";
  const report = (...rules: string[]) => sarif("Trivy", rules.map((r) => ({ rule: r, level: "error" as const, resource: `deployment/${r}`, benchmark: "CIS Kubernetes 1.9", control: "5.2.1", section: "Pod security" })), { passed: 8, failed: rules.length, total: 8 + rules.length });
  const send = (body = report("a")) => auth(INGEST_TOKEN, body);
  const path = (query: string) => `/api/v1/scans?${query}`;

  it("product and health", async () => {
    await call("GET", "/api/v1/version");
    await call("GET", "/api/v1/products", admin());
    await call("GET", "/api/v1/products", {});
    await call("GET", "/healthz");
    await call("GET", "/readyz");
    await call("GET", "/metrics");
  });

  it("targets: add and change", async () => {
    target = ((await call("POST", "/api/v1/targets", admin({ name: "prod-cluster", kind: "kubernetes", benchmark: "CIS Kubernetes 1.9" }))).body as { id: string }).id;
    await call("POST", "/api/v1/targets", admin({ name: "prod-cluster", kind: "host" }));
    await call("POST", "/api/v1/targets", admin({ name: "x", kind: "mainframe" }));
    await call("POST", "/api/v1/targets", admin("nope"));
    await call("POST", "/api/v1/targets", {});
    await call("GET", "/api/v1/targets", admin());
    await call("GET", "/api/v1/targets", admin(), "/api/v1/targets?limit=1");
    await call("GET", "/api/v1/targets", admin(), "/api/v1/targets?limit=0");
    await call("GET", "/api/v1/targets", {});
    await call("GET", "/api/v1/targets/{id}", admin(), `/api/v1/targets/${target}`);
    await call("GET", "/api/v1/targets/{id}", admin(), "/api/v1/targets/missing");
    await call("PATCH", "/api/v1/targets/{id}", admin({ failOn: "critical", benchmark: null }), `/api/v1/targets/${target}`);
    await call("PATCH", "/api/v1/targets/{id}", admin({ failOn: "urgent" }), `/api/v1/targets/${target}`);
    await call("PATCH", "/api/v1/targets/{id}", admin("nope"), `/api/v1/targets/${target}`);
    await call("PATCH", "/api/v1/targets/{id}", admin({ failOn: "high" }), "/api/v1/targets/missing");
    await call("PATCH", "/api/v1/targets/{id}", { method: "PATCH" }, `/api/v1/targets/${target}`);
  });

  it("reports and every refusal", async () => {
    await call("POST", "/api/v1/scans", send(), path("target=prod-cluster"));
    const second = (await call("POST", "/api/v1/scans", send(report("a", "b")), path("target=prod-cluster&engine=trivy"))).body as { id: string; findings: Array<{ fingerprint: string }> };
    fingerprint = second.findings[0]!.fingerprint;
    await call("POST", "/api/v1/scans", send(), path("target=missing"));
    await call("POST", "/api/v1/scans", send("{nope"), path("target=prod-cluster"));
    await call("POST", "/api/v1/scans", send(JSON.stringify({ hello: 1 })), path("target=prod-cluster"));
    await call("POST", "/api/v1/scans", send(), path("engine=trivy"));
    await call("POST", "/api/v1/scans", auth("wrong", report("a")), path("target=prod-cluster"));
    await call("POST", "/api/v1/scans", { method: "POST" }, path("target=prod-cluster"));
    await call("GET", "/api/v1/scans/{id}", admin(), `/api/v1/scans/${second.id}`);
    await call("GET", "/api/v1/scans/{id}", admin(), "/api/v1/scans/missing");
    await call("GET", "/api/v1/scans/{id}", {}, `/api/v1/scans/${second.id}`);
    await call("GET", "/api/v1/targets/{id}/scans", admin(), `/api/v1/targets/${target}/scans`);
    await call("GET", "/api/v1/targets/{id}/scans", admin(), "/api/v1/targets/missing/scans");
    await call("GET", "/api/v1/targets/{id}/scans", admin(), `/api/v1/targets/${target}/scans?cursor=junk`);
    await call("GET", "/api/v1/targets/{id}/scans", {}, `/api/v1/targets/${target}/scans`);
    await call("GET", "/api/v1/targets/{id}/history", admin(), `/api/v1/targets/${target}/history`);
    await call("GET", "/api/v1/targets/{id}/history", admin(), "/api/v1/targets/missing/history");
    await call("GET", "/api/v1/targets/{id}/history", {}, `/api/v1/targets/${target}/history`);
  });

  it("findings and decisions", async () => {
    const { body } = await call("GET", "/api/v1/findings", admin());
    expect((body as { findings: unknown[] }).findings).toHaveLength(2);
    await call("GET", "/api/v1/findings", admin(), "/api/v1/findings?status=resolved&severity=high,critical&q=deployment&benchmark=CIS%20Kubernetes%201.9&section=Pod%20security&limit=1");
    await call("GET", "/api/v1/findings", admin(), `/api/v1/findings?target=${target}`);
    await call("GET", "/api/v1/findings", admin(), "/api/v1/findings?severity=urgent");
    await call("GET", "/api/v1/findings", {});
    await call("GET", "/api/v1/facets", admin());
    await call("GET", "/api/v1/facets", {});
    await call("GET", "/api/v1/targets/{id}/findings", admin(), `/api/v1/targets/${target}/findings`);
    await call("GET", "/api/v1/targets/{id}/findings", admin(), `/api/v1/targets/${target}/findings?status=suppressed`);
    await call("GET", "/api/v1/targets/{id}/findings", admin(), "/api/v1/targets/missing/findings");
    await call("GET", "/api/v1/targets/{id}/findings", {}, `/api/v1/targets/${target}/findings`);

    const put = (fp: string, state: unknown) => call("PUT", "/api/v1/targets/{id}/findings/{fingerprint}", admin(state), `/api/v1/targets/${target}/findings/${fp}`);
    await put(fingerprint, { state: "false-positive", reason: "A test namespace" });
    await put(fingerprint, { state: "compensating", reason: "A network policy covers it" });
    await put(fingerprint, { state: "accepted", reason: "Until the migration", expiresAt: inDays(30) });
    await put(fingerprint, { state: "accepted", reason: "No end" });
    await put(fingerprint, "nope");
    await put("missing", { state: "open" });
    await call("GET", "/api/v1/targets/{id}/findings", admin(), `/api/v1/targets/${target}/findings?status=suppressed`);
    await put(fingerprint, { state: "open" });
    await call("PUT", "/api/v1/targets/{id}/findings/{fingerprint}", { method: "PUT" }, `/api/v1/targets/${target}/findings/${fingerprint}`);
    await call("GET", "/api/v1/summary", admin());
    await call("GET", "/api/v1/summary", {});
  });

  it("deletes a target", async () => {
    await call("DELETE", "/api/v1/targets/{id}", admin(), `/api/v1/targets/${target}`);
    await call("DELETE", "/api/v1/targets/{id}", admin(), `/api/v1/targets/${target}`);
    await call("DELETE", "/api/v1/targets/{id}", { method: "DELETE" }, "/api/v1/targets/x");
  });

  it("covers every operation in openapi.json", () => {
    const all = Object.entries(spec.paths).flatMap(([path, ops]) => Object.keys(ops).map((m) => `${m.toUpperCase()} ${path}`));
    expect([...covered].sort()).toEqual(all.sort());
  });
});
