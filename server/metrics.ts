// Prometheus text exposition, written by hand: a few lines, no client library needed.
const requests = new Map<string, number>();

export function countRequest(method: string, route: string, status: number) {
  const key = `method="${method}",route="${route}",status="${status}"`;
  requests.set(key, (requests.get(key) ?? 0) + 1);
}

export interface Gauges {
  targets: number;
  /** Open failed controls by severity, without decided ones. */
  findings: Record<string, number>;
  suppressed: number;
  /** Reports of the last 7 days that failed their check. */
  failingChecks: number;
  /** The newest score of each target; null when no report had one. */
  scores: Array<{ target: string; score: number | null }>;
}

export function renderMetrics(version: string, g: Gauges): string {
  const lines = [
    "# HELP openasy_build_info Build information.",
    "# TYPE openasy_build_info gauge",
    `openasy_build_info{product="posture",version="${version}"} 1`,
    "# HELP openasy_http_requests_total HTTP requests handled.",
    "# TYPE openasy_http_requests_total counter",
    ...[...requests].map(([labels, n]) => `openasy_http_requests_total{${labels}} ${n}`),
    "# HELP openasy_posture_targets Targets whose configuration is judged.",
    "# TYPE openasy_posture_targets gauge",
    `openasy_posture_targets ${g.targets}`,
    "# HELP openasy_posture_open_findings Open failed controls by severity, without decided ones.",
    "# TYPE openasy_posture_open_findings gauge",
    ...Object.entries(g.findings).map(([s, n]) => `openasy_posture_open_findings{severity="${s}"} ${n}`),
    "# HELP openasy_posture_suppressed_findings Failed controls that someone marked as a false positive, accepted risk or compensated.",
    "# TYPE openasy_posture_suppressed_findings gauge",
    `openasy_posture_suppressed_findings ${g.suppressed}`,
    "# HELP openasy_posture_failing_checks Reports of the last 7 days that failed their check.",
    "# TYPE openasy_posture_failing_checks gauge",
    `openasy_posture_failing_checks ${g.failingChecks}`,
    "# HELP openasy_posture_score Share of checks that passed in the newest report of a target, 0 to 100.",
    "# TYPE openasy_posture_score gauge",
    ...g.scores.filter((s) => s.score !== null).map((s) => `openasy_posture_score{target="${s.target}"} ${s.score}`),
    "# HELP process_uptime_seconds Seconds since the process started.",
    "# TYPE process_uptime_seconds gauge",
    `process_uptime_seconds ${process.uptime().toFixed(0)}`,
  ];
  return lines.join("\n") + "\n";
}
