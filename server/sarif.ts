import { createHash } from "node:crypto";

export type Severity = "critical" | "high" | "medium" | "low";
export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

export interface Finding {
  /** Stable across reports: the control and the resource it failed on. */
  fingerprint: string;
  ruleId: string;
  severity: Severity;
  resource: string;
  benchmark: string | null;
  control: string | null;
  section: string | null;
  message: string;
}

export class SarifError extends Error {}

/** Most results one report may hold. */
export const MAX_RESULTS = 50_000;

type Obj = Record<string, any>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);
const text = (v: unknown, max: number) => (typeof v === "string" && v.trim() ? v.trim().slice(0, max) : null);
const count = (v: unknown) => (typeof v === "number" && Number.isInteger(v) && v >= 0 ? v : null);

function fromScore(score: unknown): Severity | null {
  const n = typeof score === "string" ? Number(score) : score;
  if (typeof n !== "number" || !Number.isFinite(n) || n <= 0) return null;
  return n >= 9 ? "critical" : n >= 7 ? "high" : n >= 4 ? "medium" : "low";
}

const fromLevel = (level: unknown): Severity => (level === "error" ? "high" : level === "note" ? "low" : "medium");

/** Passwords, tokens and keys in a message or a resource name are replaced before anything is stored (ADR 0045). */
export function mask(value: string): string {
  return value
    .replace(/((?:password|passwd|pwd|token|secret|api[_-]?key|access[_-]?key)["']?\s*[=:]\s*["']?)[^\s&"',;]+/gi, "$1***")
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/g, "Bearer ***")
    .replace(/\b(?:AKIA|ASIA|ghp_|glpat-|xox[abp]-)[A-Za-z0-9_-]{8,}/g, "***");
}

export interface Parsed {
  tool: string;
  findings: Finding[];
  /** Results that failed but name no resource, so they cannot be followed from one report to the next. */
  skipped: number;
  /** The report's own count of checks, or the count of its passed and failed results; null when it gives none. */
  checks: { total: number; passed: number } | null;
}

/** Reads a SARIF 2.1.0 report from Trivy, kubescape, checkov, Prowler or another checker of configuration. */
export function parseSarif(body: unknown): Parsed {
  if (!isObj(body) || !Array.isArray(body.runs))
    throw new SarifError("Send a SARIF 2.1.0 log: a JSON object with a runs array, for example from `trivy config --format sarif`.");
  if (typeof body.version === "string" && !body.version.startsWith("2.1")) throw new SarifError(`SARIF ${body.version} is not supported; send version 2.1.0.`);
  const tools: string[] = [];
  const found: Finding[] = [];
  let skipped = 0;
  let passedResults = 0;
  let summary = null as { total: number; passed: number } | null;
  for (const run of body.runs) {
    if (!isObj(run)) continue;
    const driver = isObj(run.tool) && isObj(run.tool.driver) ? run.tool.driver : {};
    const name = text(driver.name, 64);
    if (name && !tools.includes(name)) tools.push(name);
    const s = isObj(run.properties) && isObj(run.properties.summary) ? run.properties.summary : null;
    if (s) {
      const passed = count(s.passed);
      const failed = count(s.failed);
      const total = count(s.total) ?? (passed !== null && failed !== null ? passed + failed : null);
      if (passed !== null && total !== null && passed <= total) summary = { total: (summary?.total ?? 0) + total, passed: (summary?.passed ?? 0) + passed };
    }
    const rules = new Map<string, Obj>();
    if (Array.isArray(driver.rules)) for (const r of driver.rules) if (isObj(r) && typeof r.id === "string") rules.set(r.id, r);
    for (const result of Array.isArray(run.results) ? run.results : []) {
      if (!isObj(result) || (Array.isArray(result.suppressions) && result.suppressions.length > 0)) continue;
      if (result.kind === "pass") {
        passedResults++;
        continue;
      }
      if (result.kind !== undefined && result.kind !== "fail") continue; // review, open, notApplicable, informational
      if (found.length >= MAX_RESULTS) throw new SarifError(`A report may hold at most ${MAX_RESULTS} results.`);
      const ruleId = text(result.ruleId ?? (isObj(result.rule) ? result.rule.id : undefined), 256) ?? "unknown";
      const rule = rules.get(ruleId);
      const props = isObj(result.properties) ? result.properties : {};
      const ruleProps = isObj(rule?.properties) ? rule!.properties : {};
      const location = Array.isArray(result.locations) && isObj(result.locations[0]) ? result.locations[0] : {};
      const physical = isObj(location.physicalLocation) ? location.physicalLocation : {};
      const logical = Array.isArray(location.logicalLocations) && isObj(location.logicalLocations[0]) ? location.logicalLocations[0] : {};
      const resource = text(
        props.resource ?? logical.fullyQualifiedName ?? logical.name ?? (isObj(physical.artifactLocation) ? physical.artifactLocation.uri : undefined),
        512,
      );
      if (!resource) {
        skipped++;
        continue;
      }
      found.push({
        fingerprint: "",
        ruleId,
        severity:
          fromScore(props["security-severity"]) ??
          fromScore(ruleProps["security-severity"]) ??
          fromLevel(result.level ?? (isObj(rule?.defaultConfiguration) ? rule!.defaultConfiguration.level : undefined)),
        resource: mask(resource),
        benchmark: text(props.benchmark ?? ruleProps.benchmark, 128),
        control: text(props.control ?? ruleProps.control, 64),
        section: text(props.section ?? ruleProps.section, 128),
        message: mask(
          text(isObj(result.message) ? (result.message.text ?? result.message.markdown) : undefined, 500) ??
            text(isObj(rule?.shortDescription) ? rule!.shortDescription.text : undefined, 500) ??
            ruleId,
        ),
      });
    }
  }
  // A control that fails twice on one resource is one finding.
  const seen = new Set<string>();
  const findings: Finding[] = [];
  for (const f of found) {
    const fingerprint = createHash("sha256").update(`${f.ruleId}\n${f.resource}`).digest("hex").slice(0, 32);
    if (seen.has(fingerprint)) continue;
    seen.add(fingerprint);
    findings.push({ ...f, fingerprint });
  }
  const checks = summary ?? (passedResults > 0 ? { total: passedResults + findings.length, passed: passedResults } : null);
  return { tool: tools.join(", ") || "unknown", findings, skipped, checks };
}
