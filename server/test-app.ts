// Starts the app on a random port for tests.
import { createServer, type RequestListener, type Server } from "node:http";
import { createAuth } from "@openasy/auth";
import type { AddressInfo } from "node:net";
import { createApp, type AppOptions } from "./app.ts";
import { openDb } from "./db.ts";
import { createPosture } from "./posture.ts";

export const INGEST_TOKEN = "test-ingest-token";
export const ADMIN_TOKEN = "test-admin-token";

export interface TestResult {
  rule: string;
  /** SARIF level. */
  level?: "error" | "warning" | "note";
  score?: number;
  resource?: string;
  /** Written as a SARIF kind: "pass" results are controls that passed. */
  kind?: "pass" | "fail" | "review";
  benchmark?: string;
  control?: string;
  section?: string;
  message?: string;
}

/** A SARIF 2.1.0 log such as Trivy, kubescape or checkov write. */
export function sarif(tool: string, results: TestResult[], summary?: { passed: number; failed: number; total: number }) {
  return JSON.stringify({
    version: "2.1.0",
    runs: [
      {
        tool: { driver: { name: tool, rules: [] } },
        ...(summary && { properties: { summary } }),
        results: results.map((r) => ({
          ruleId: r.rule,
          level: r.level ?? "warning",
          ...(r.kind && { kind: r.kind }),
          message: { text: r.message ?? `${r.rule} failed` },
          properties: {
            ...(r.score !== undefined && { "security-severity": String(r.score) }),
            ...(r.resource && { resource: r.resource }),
            ...(r.benchmark && { benchmark: r.benchmark }),
            ...(r.control && { control: r.control }),
            ...(r.section && { section: r.section }),
          },
          locations: [{ physicalLocation: { artifactLocation: { uri: "manifest.yaml" } } }],
        })),
      },
    ],
  });
}

export async function startApp(opts: Partial<AppOptions> & { version: string }) {
  const db = openDb(":memory:");
  const posture = createPosture(db);
  // The origin is known once the port is, so the handler is set after listening.
  let handler: RequestListener = (_req, res) => res.writeHead(503).end();
  const server: Server = createServer((req, res) => handler(req, res));
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const base = `http://localhost:${(server.address() as AddressInfo).port}`;
  const auth = createAuth({ db, product: "posture", productName: "OpenAsy Posture", origin: base });
  handler = createApp({ db, posture, auth, ingestToken: INGEST_TOKEN, adminToken: ADMIN_TOKEN, ...opts });
  const as =
    (token: string) =>
    (path: string, init: RequestInit = {}) =>
      fetch(base + path, { ...init, headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...init.headers } });
  const admin = as(ADMIN_TOKEN);
  const ingest = as(INGEST_TOKEN);
  /** Sends a report the way CI does. */
  const scan = (query: Record<string, string>, body: string | Buffer) => ingest(`/api/v1/scans?${new URLSearchParams(query)}`, { method: "POST", body });
  const close = () => new Promise<void>((resolve) => server.close(() => resolve()));
  return { db, posture, auth, base, admin, ingest, scan, close };
}
