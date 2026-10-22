// The UI is an ordinary client of the public API (ADR 0014, 0018). Types follow openapi.json.

export type Severity = "critical" | "high" | "medium" | "low";
export type FailOn = Severity | "none";
export type Counts = Record<Severity, number>;

/** Another OpenAsy product of this install, from OPENASY_PRODUCTS. */
export interface ProductLink {
  id: string;
  url: string;
}

export interface Summary {
  targets: number;
  open: Counts;
  suppressed: number;
  failingChecks: number;
  lastScanAt: string | null;
  averageScore: number | null;
}

export type Kind = "cloud" | "kubernetes" | "host";

export interface Target {
  id: string;
  name: string;
  kind: Kind;
  benchmark: string | null;
  failOn: FailOn;
  score: number | null;
  open: Counts;
  suppressed: number;
  lastScan: { at: string; engine: string; new: number; passed: boolean } | null;
  createdAt: string;
}

export interface TriageState {
  state: "false-positive" | "accepted" | "compensating";
  reason: string;
  by: string | null;
  at: string | null;
  expiresAt: string | null;
  active: boolean;
}

export interface Finding {
  target: { id: string; name: string };
  fingerprint: string;
  engine: string;
  rule: string;
  severity: Severity;
  resource: string;
  benchmark: string | null;
  control: string | null;
  section: string | null;
  message: string;
  firstSeen: string;
  lastSeen: string;
  resolvedAt: string | null;
  triage: TriageState | null;
}

export interface Scan {
  id: string;
  target: { id: string; name: string };
  engine: string;
  tool: string;
  total: number;
  checks: { total: number; passed: number } | null;
  score: number | null;
  new: number;
  resolved: number;
  suppressed: number;
  ignored: number;
  blocking: number;
  failOn: FailOn;
  passed: boolean;
  createdAt: string;
}

export interface History {
  points: Array<{ at: string; engine: string; score: number; passed: number; total: number }>;
}

export class Unauthorized extends Error {}
/** The signed-in owner or admin has no second factor yet; the sign-in gate asks for one. */
export class MfaSetupRequired extends Error {}
export class ApiError extends Error {}

// The session is an HttpOnly cookie set by sign-in (@openasy/auth); the browser sends it, nothing is stored here.
export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(path, { ...init, credentials: "same-origin", headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...init.headers } });
  if (!res.ok) {
    const problem = (await res.json().catch(() => ({}))) as { code?: string; detail?: string };
    if (res.status === 401) throw new Unauthorized(problem.detail);
    if (problem.code === "mfa-setup-required") throw new MfaSetupRequired(problem.detail);
    throw new ApiError(problem.detail ?? `${path}: ${res.status}`);
  }
  return (res.status === 204 ? undefined : await res.json()) as T;
}
