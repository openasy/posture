// What the search window (Cmd+K) finds in Posture: targets by name, and open failed controls by control, rule, resource or message, from the API.
import type { SearchFn, SearchResult } from "@openasy/ui";
import { ClipboardCheck, ShieldCheck } from "lucide-react";
import type { Finding, Target } from "./api.ts";
import type { T } from "./i18n.ts";

type Call = <R>(path: string, init?: RequestInit) => Promise<R>;

export function search(call: Call, t: T): SearchFn {
  return async (q, signal) => {
    const [list, found] = await Promise.all([
      call<{ targets: Target[] }>("/api/v1/targets?limit=500", { signal }),
      call<{ findings: Finding[] }>(`/api/v1/findings?${new URLSearchParams({ q, limit: "8" })}`, { signal }),
    ]);
    const named: SearchResult[] = list.targets
      .filter((e) => e.name.toLowerCase().includes(q))
      .slice(0, 6)
      .map((e) => ({
        id: `target:${e.id}`,
        label: e.name,
        detail: e.benchmark ?? t("search.noBenchmark"),
        kind: t("search.target"),
        icon: ShieldCheck,
        mono: false,
        href: `/targets/${encodeURIComponent(e.id)}`,
      }));
    const findings: SearchResult[] = found.findings.map((f) => ({
      id: `control:${f.target.id}:${f.fingerprint}`,
      label: f.control ?? f.rule,
      detail: `${f.message} · ${f.resource} · ${f.target.name}`,
      kind: t("search.control"),
      icon: ClipboardCheck,
      severity: f.severity,
      mono: false,
      href: `/targets/${encodeURIComponent(f.target.id)}`,
    }));
    return [...named, ...findings];
  };
}
