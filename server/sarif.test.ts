import { describe, expect, it } from "vitest";
import { mask, parseSarif, SarifError } from "./sarif.ts";
import { sarif, type TestResult } from "./test-app.ts";

const parse = (results: TestResult[], summary?: { passed: number; failed: number; total: number }) => parseSarif(JSON.parse(sarif("Trivy", results, summary)));

describe("parseSarif", () => {
  it("reads the control, the resource and where it belongs", () => {
    const { tool, findings } = parse([{ rule: "KSV017", level: "error", resource: "deployment/web", benchmark: "CIS Kubernetes 1.9", control: "5.2.1", section: "Pod security", message: "Container runs privileged" }]);
    expect(tool).toBe("Trivy");
    expect(findings).toEqual([
      { fingerprint: expect.stringMatching(/^[0-9a-f]{32}$/), ruleId: "KSV017", severity: "high", resource: "deployment/web", benchmark: "CIS Kubernetes 1.9", control: "5.2.1", section: "Pod security", message: "Container runs privileged" },
    ]);
  });

  it("takes severity from security-severity first, then from the level", () => {
    const sev = (r: Omit<TestResult, "resource">) => parse([{ ...r, resource: "r" }]).findings[0]!.severity;
    expect(sev({ rule: "a", score: 9.8 })).toBe("critical");
    expect(sev({ rule: "a", score: 7.5, level: "note" })).toBe("high");
    expect(sev({ rule: "a", score: 5 })).toBe("medium");
    expect(sev({ rule: "a", score: 2 })).toBe("low");
    expect(sev({ rule: "a", level: "error" })).toBe("high");
    expect(sev({ rule: "a" })).toBe("medium");
    expect(sev({ rule: "a", level: "note" })).toBe("low");
  });

  it("follows a failed control by rule and resource, and counts a repeat once", () => {
    const fp = (rule: string, resource: string) => parse([{ rule, resource }]).findings[0]!.fingerprint;
    expect(fp("a", "deployment/web")).toBe(fp("a", "deployment/web"));
    expect(fp("a", "deployment/web")).not.toBe(fp("a", "deployment/api"));
    expect(fp("a", "deployment/web")).not.toBe(fp("b", "deployment/web"));
    expect(parse([{ rule: "a", resource: "x" }, { rule: "a", resource: "x" }]).findings).toHaveLength(1);
  });

  it("leaves out controls that passed, are not failures or name no resource, and says how many had none", () => {
    const log = JSON.parse(sarif("Trivy", [{ rule: "ok", resource: "a", kind: "pass" }, { rule: "look", resource: "b", kind: "review" }, { rule: "bad", resource: "c", kind: "fail" }, { rule: "sup", resource: "d" }]));
    log.runs[0].results[3].suppressions = [{ kind: "external" }];
    log.runs[0].results.push({ ruleId: "nowhere", message: { text: "no place" }, locations: [{ physicalLocation: {} }] });
    const parsed = parseSarif(log);
    expect(parsed.findings.map((f) => f.ruleId)).toEqual(["bad"]);
    expect(parsed.skipped).toBe(1);
  });

  it("uses a logical location as the resource when the result names none", () => {
    const log = JSON.parse(sarif("kubescape", [{ rule: "C-0017" }]));
    log.runs[0].results[0].locations = [{ logicalLocations: [{ fullyQualifiedName: "default/Deployment/web" }] }];
    expect(parseSarif(log).findings[0]!.resource).toBe("default/Deployment/web");
  });

  it("counts checks from the report's summary, or from its passed results", () => {
    expect(parse([{ rule: "a", resource: "x" }], { passed: 90, failed: 10, total: 100 }).checks).toEqual({ total: 100, passed: 90 });
    expect(parse([{ rule: "p", resource: "x", kind: "pass" }, { rule: "p2", resource: "y", kind: "pass" }, { rule: "f", resource: "z" }]).checks).toEqual({ total: 3, passed: 2 });
    expect(parse([{ rule: "a", resource: "x" }]).checks).toBeNull();
    expect(parse([{ rule: "a", resource: "x" }], { passed: 5, failed: 0, total: 3 }).checks).toBeNull();
  });

  it("masks credentials in resource names and messages", () => {
    const f = parse([{ rule: "a", resource: "configmap/app password=hunter2", message: "env token=abcdef123 and Bearer abcdefghijklmnop" }]).findings[0]!;
    expect(f.resource + f.message).not.toMatch(/hunter2|abcdef123|abcdefghijklmnop/);
  });

  it("refuses what is not SARIF 2.1", () => {
    expect(() => parseSarif([])).toThrow(SarifError);
    expect(() => parseSarif({ hello: 1 })).toThrow(SarifError);
    expect(() => parseSarif({ version: "1.0.0", runs: [] })).toThrow(/not supported/);
    expect(parseSarif({ version: "2.1.0", runs: [] })).toEqual({ tool: "unknown", findings: [], skipped: 0, checks: null });
  });
});

describe("mask", () => {
  it("hides tokens by their prefix too", () => {
    expect(mask("ghp_abcdefghijklmnopqrstu leaked")).toBe("*** leaked");
  });
});
