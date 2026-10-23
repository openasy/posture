import {
  AppShell,
  Badge,
  BrandProvider,
  Button,
  Callout,
  DataTable,
  Dialog,
  EmptyState,
  FacetFilter,
  FilterBar,
  IconButton,
  KpiCard,
  KpiGrid,
  navigate,
  PageHeader,
  Panel,
  PRODUCT_IDS,
  SearchInput,
  SelectField,
  SeverityBadge,
  StatusBadge,
  Tabs,
  TextField,
  usePath,
  type Column,
  type ProductId,
  useThemePreference,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAuth } from "@openasy/auth/react";
import { Bug, CircleSlash, Crosshair, KeyRound, LogIn, LogOut, Plus, Settings2, Trash2, UserRound, Users, X } from "lucide-react";
import { useCallback, useEffect, useState, type FormEvent, type ReactNode } from "react";
import { api, MfaSetupRequired, Unauthorized, type FailOn, type Finding, type History, type Kind, type ProductLink, type Scan, type Severity, type HostsCoverage, type Summary, type Target } from "./api.ts";

function ago(iso: string | null | undefined): string {
  if (!iso) return "never";
  const s = Math.round((Date.now() - Date.parse(iso)) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86_400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86_400)} d ago`;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

const PAGES = ["targets", "setup", "account", "members", "signin", "tokens"] as const;
type Route = { page: "findings" | (typeof PAGES)[number] } | { page: "target"; id: string };
/** The first path segments that are pages of this UI, for followLinks. */
export const PATHS = ["findings", ...PAGES];
function parseRoute(path: string): Route {
  const [page, id] = path.replace(/^\//, "").split("/");
  if (page === "targets" && id) return { page: "target", id: decodeURIComponent(id) };
  if ((PAGES as readonly string[]).includes(page ?? "")) return { page: page as (typeof PAGES)[number] };
  return { page: "findings" };
}

/** Data loading with the session; when it ends, the sign-in screen comes back. */
function useApi() {
  const { expired, refresh } = useAuth();
  return useCallback(
    async <T,>(path: string, init?: RequestInit): Promise<T> => {
      try {
        return await api<T>(path, init);
      } catch (err) {
        if (err instanceof Unauthorized) expired();
        if (err instanceof MfaSetupRequired) void refresh();
        throw err;
      }
    },
    [expired, refresh],
  );
}
type Call = ReturnType<typeof useApi>;

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const FAIL_ON: Array<{ value: FailOn; label: string }> = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High or worse" },
  { value: "medium", label: "Medium or worse" },
  { value: "low", label: "Any finding" },
  { value: "none", label: "Never fail" },
];

/** Compact severity counts; each badge carries the full name for screen readers. */
function SevCounts({ counts }: { counts: Record<Severity, number> }) {
  const shown = SEVERITIES.filter((s) => counts[s] > 0);
  if (!shown.length) return <span className="text-xs text-fg-muted">None</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {shown.map((s) => (
        <Badge key={s} tone={s === "low" ? "neutral" : s === "medium" ? "warning" : "danger"}>
          <span className="sr-only">{s} </span>
          {counts[s]}
        </Badge>
      ))}
    </span>
  );
}

function Code({ children }: { children: ReactNode }) {
  return <pre className="m-0 overflow-x-auto rounded-md bg-subtle px-2.5 py-2 font-mono text-xs text-fg">{children}</pre>;
}

function FindingPanel({ finding, call, onClose, onChanged }: { finding: Finding; call: Call; onClose: () => void; onChanged: () => void }) {
  const { can } = useAuth();
  const [deciding, setDeciding] = useState(false);
  const [state, setState] = useState<"false-positive" | "accepted" | "compensating">("compensating");
  const [days, setDays] = useState("90");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string>();
  const close = () => (setDeciding(false), setReason(""), setError(undefined));
  const url = `/api/v1/targets/${finding.target.id}/findings/${finding.fingerprint}`;

  const decide = async (e: FormEvent) => {
    e.preventDefault();
    try {
      await call(url, { method: "PUT", body: JSON.stringify({ state, reason, ...(state === "accepted" && { expiresAt: new Date(Date.now() + Number(days) * 86_400_000).toISOString() }) }) });
      close();
      onChanged();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  const reopen = () => call(url, { method: "PUT", body: JSON.stringify({ state: "open" }) }).then(onChanged, () => {});
  const t = finding.triage;

  return (
    <Panel
      aria-label={`${finding.rule} details`}
      title={<span className="posture-wrap font-mono text-sm">{finding.rule}</span>}
      description={`${finding.target.name} · ${finding.engine}`}
      actions={
        <IconButton label="Close details" size="sm" onClick={onClose}>
          <X />
        </IconButton>
      }
    >
      <div className="flex flex-col gap-3 text-sm">
        <div className="flex flex-wrap items-center gap-1.5">
          <SeverityBadge severity={finding.severity} />
          {finding.control && <Badge mono>{finding.control}</Badge>}
          {finding.section && <Badge>{finding.section}</Badge>}
        </div>
        <span className="posture-wrap font-mono text-xs">{finding.resource}</span>
        <p className="m-0 text-fg-muted">{finding.message}</p>
        {finding.benchmark && <p className="m-0 text-xs text-fg-muted">{finding.benchmark}</p>}
        {t && (
          <div className="flex flex-col gap-1 rounded-md border border-line p-2.5 text-xs">
            <span>
              <StatusBadge tone={t.active ? "success" : "neutral"}>{t.state === "compensating" ? "Compensating control" : t.state === "false-positive" ? "False positive" : t.active ? "Accepted risk" : "Acceptance expired"}</StatusBadge>
            </span>
            <span>{t.reason}</span>
            <span className="text-fg-muted">
              {t.by ? `${t.by}, ` : ""}
              {ago(t.at)}
              {t.expiresAt ? `, until ${new Date(t.expiresAt).toLocaleDateString()}` : ""}
            </span>
          </div>
        )}
        {can("editor") && (
          <div className="flex gap-2 border-t border-line pt-3">
            <Button size="sm" icon={<CircleSlash />} onClick={() => setDeciding(true)}>
              {t ? "Change decision" : "Triage"}
            </Button>
            {t && (
              <Button size="sm" onClick={() => void reopen()}>
                Open again
              </Button>
            )}
          </div>
        )}
        <Dialog
          open={deciding}
          onOpenChange={(open) => !open && close()}
          title={`Triage ${finding.rule}`}
          description="The decision stays with this finding across reports, so it does not fail the next check. Say why, for the next review."
          onSubmit={decide}
          footer={
            <>
              <Button type="button" onClick={close}>
                Cancel
              </Button>
              <Button type="submit" variant="primary" disabled={reason.trim().length < 3}>
                Save decision
              </Button>
            </>
          }
        >
          <SelectField
            label="Decision"
            value={state}
            onChange={(e) => setState(e.target.value as typeof state)}
            options={[
              { value: "compensating", label: "Compensating control: something else covers it" },
              { value: "false-positive", label: "False positive" },
              { value: "accepted", label: "Accepted risk" },
            ]}
          />
          <TextField label="Reason" value={reason} onChange={(e) => setReason(e.target.value)} hint="Why, for the next review." error={error} />
          {state === "accepted" && (
            <SelectField
              label="For"
              value={days}
              onChange={(e) => setDays(e.target.value)}
              options={[
                { value: "30", label: "30 days" },
                { value: "90", label: "90 days" },
                { value: "180", label: "180 days" },
                { value: "365", label: "1 year" },
              ]}
            />
          )}
        </Dialog>
      </div>
    </Panel>
  );
}

type Tab = "open" | "suppressed" | "resolved";

/** Findings of every target, or of one when targetId is given. */
function FindingsTable({ call, targetId, summary, reload }: { call: Call; targetId?: string; summary?: { open: Record<Severity, number> }; reload: () => void }) {
  const [tab, setTab] = useState<Tab>("open");
  const [sev, setSev] = useState<string[]>([]);
  const [q, setQ] = useState("");
  const [benchmark, setBenchmark] = useState<string[]>([]);
  const [section, setSection] = useState<string[]>([]);
  const [facets, setFacets] = useState<{ benchmarks: string[]; sections: string[] }>({ benchmarks: [], sections: [] });
  const [rows, setRows] = useState<Finding[]>();
  const [more, setMore] = useState<string>();
  const [open, setOpen] = useState<Finding | null>(null);
  const base = targetId ? `/api/v1/targets/${targetId}/findings` : "/api/v1/findings";

  const query = useCallback(
    (cursor?: string) => {
      const p = new URLSearchParams({ status: tab, limit: "200" });
      if (sev.length) p.set("severity", sev.join(","));
      if (q.trim()) p.set("q", q.trim());
      if (benchmark.length === 1) p.set("benchmark", benchmark[0]!);
      if (section.length === 1) p.set("section", section[0]!);
      if (cursor) p.set("cursor", cursor);
      return call<{ findings: Finding[]; nextCursor?: string }>(`${base}?${p}`);
    },
    [call, base, tab, sev, q, benchmark, section],
  );
  const load = useCallback(() => {
    query().then((r) => (setRows(r.findings), setMore(r.nextCursor)), () => setRows([]));
  }, [query]);
  useEffect(load, [load]);
  useEffect(() => void call<{ benchmarks: string[]; sections: string[] }>("/api/v1/facets").then(setFacets, () => {}), [call]);
  const loadMore = () => more && query(more).then((r) => (setRows((x) => [...(x ?? []), ...r.findings]), setMore(r.nextCursor)));

  const columns: Column<Finding>[] = [
    { id: "sev", header: "Severity", width: "104px", cell: (f) => <SeverityBadge severity={f.severity} /> },
    {
      id: "rule",
      header: "Rule",
      width: "30%",
      cell: (f) => (
        <span className="flex min-w-0 flex-col">
          <button type="button" className="posture-wrap self-start text-left font-mono text-xs font-medium text-fg hover:underline">
            {f.rule}
          </button>
          <span className="posture-clamp text-xs text-fg-muted" title={f.message}>
            {f.message}
          </span>
        </span>
      ),
    },
    {
      id: "where",
      header: "Resource",
      width: "32%",
      cell: (f) => (
        <span className="posture-wrap font-mono text-xs">
          {f.resource}
          {f.control ? <span className="text-fg-muted"> · {f.control}</span> : null}
        </span>
      ),
    },
    { id: "engine", header: "Engine", cell: (f) => <Badge>{f.engine}</Badge> },
    ...(targetId ? [] : [{ id: "target", header: "Target", cell: (f: Finding) => <span className="text-xs">{f.target.name}</span> } satisfies Column<Finding>]),
    { id: "seen", header: "First seen", sortValue: (f) => f.firstSeen, cell: (f) => <span className="text-xs whitespace-nowrap">{ago(f.firstSeen)}</span> },
  ];

  return (
    <>
      <Tabs<Tab>
        label="Finding views"
        value={tab}
        onChange={setTab}
        items={[
          { value: "open", label: "Open" },
          { value: "suppressed", label: "Decided" },
          { value: "resolved", label: "Fixed" },
        ]}
      />
      <FilterBar onClear={() => (setSev([]), setQ(""), setBenchmark([]), setSection([]))}>
        <FacetFilter label="Severity" selected={sev} onChange={setSev} options={SEVERITIES.map((s) => ({ value: s, label: s.charAt(0).toUpperCase() + s.slice(1), count: tab === "open" ? summary?.open[s] : undefined }))} />
        {facets.benchmarks.length > 0 && <FacetFilter label="Benchmark" selected={benchmark} onChange={(v) => setBenchmark(v.slice(-1))} options={facets.benchmarks.map((b) => ({ value: b, label: b }))} />}
        {facets.sections.length > 0 && <FacetFilter label="Section" selected={section} onChange={(v) => setSection(v.slice(-1))} options={facets.sections.map((b) => ({ value: b, label: b }))} />}
        <SearchInput label="Search rule, control, resource or message" className="w-64" value={q} onChange={(e) => setQ(e.target.value)} />
      </FilterBar>
      <div className={open ? "grid gap-2.5 xl:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]" : "grid gap-2.5"}>
        <Panel
          title={tab === "open" ? "Open" : tab === "suppressed" ? "Decided" : "Fixed"}
          description="Controls that fail, most severe first"
          flush
          footer={
            more ? (
              <Button size="sm" onClick={loadMore}>
                Load more
              </Button>
            ) : undefined
          }
        >
          <DataTable
            label="Findings"
            columns={columns}
            rows={rows ?? []}
            loading={!rows}
            getRowId={(f) => `${f.target.id}/${f.fingerprint}`}
            onRowClick={(f) => setOpen(f)}
            activeRowId={open ? `${open.target.id}/${open.fingerprint}` : undefined}
            minWidth={900}
            pageSize={50}
            empty={
              <EmptyState title={tab === "open" ? "No open findings" : tab === "suppressed" ? "Nothing triaged" : "Nothing fixed yet"}>
                {tab === "open" && summary && !Object.values(summary.open).some(Boolean) ? (
                  <>
                    Send a report to see findings. See <a href="/setup">Setup</a>.
                  </>
                ) : (
                  "Nothing matches these filters."
                )}
              </EmptyState>
            }
          />
        </Panel>
        {open && (
          <FindingPanel
            finding={open}
            call={call}
            onClose={() => setOpen(null)}
            onChanged={() => {
              setOpen(null);
              load();
              reload();
            }}
          />
        )}
      </div>
    </>
  );
}

/** Servers in the install's hosts file Posture has no posture scan for, and the file's own problems (ADR 0052). */
function HostsCoverageNote({ file }: { file?: HostsCoverage | null }) {
  if (!file) return null;
  if (file.error) {
    return (
      <Callout tone="danger" title="The hosts file is not applied">
        {file.error} Its last good version is used until it is fixed ({file.path}).
      </Callout>
    );
  }
  if (!file.missing.length) return null;
  return (
    <Callout tone="warning" title={`${file.missing.length} ${file.missing.length === 1 ? "server" : "servers"} in the hosts file ${file.missing.length === 1 ? "has" : "have"} no posture scan`}>
      {file.missing.map((h) => h.name).join(", ")}. Send a host benchmark for each, named as the server or its address.
    </Callout>
  );
}

function FindingsPage({ call, summary, reload }: { call: Call; summary?: Summary; reload: () => void }) {
  const s = summary;
  return (
    <>
      <PageHeader title="Findings" description={s ? `${plural(s.targets, "target")} · last report ${ago(s.lastScanAt)}` : undefined} />
      <HostsCoverageNote file={s?.hostsFile} />
      {s && (
        <KpiGrid minWidth={150}>
          <KpiCard label="Average score" value={s.averageScore === null ? "–" : `${s.averageScore}%`} tone={s.averageScore === null ? "info" : s.averageScore >= 90 ? "success" : s.averageScore >= 70 ? "warning" : "danger"} />
          <KpiCard label="Critical" value={s.open.critical} footer={<SeverityBadge severity="critical" />} />
          <KpiCard label="High" value={s.open.high} footer={<SeverityBadge severity="high" />} />
          <KpiCard label="Medium" value={s.open.medium} footer={<SeverityBadge severity="medium" />} />
          <KpiCard label="Low" value={s.open.low} footer={<SeverityBadge severity="low" />} />
          <KpiCard label="Failed checks, 7 days" value={s.failingChecks} tone={s.failingChecks ? "warning" : "success"} />
        </KpiGrid>
      )}
      <FindingsTable call={call} summary={s} reload={reload} />
    </>
  );
}

function CheckStatus({ passed }: { passed: boolean }) {
  return passed ? <StatusBadge tone="success">Passed</StatusBadge> : <StatusBadge tone="danger">Failed</StatusBadge>;
}

const KIND_LABEL: Record<Kind, string> = { cloud: "Cloud account", kubernetes: "Kubernetes cluster", host: "Hosts" };

function ScoreBadge({ score }: { score: number | null }) {
  if (score === null) return <span className="text-xs text-fg-muted">No score</span>;
  return <StatusBadge tone={score >= 90 ? "success" : score >= 70 ? "warning" : "danger"}>{score}%</StatusBadge>;
}

/** The score of each report as a line, drawn here because it is one polyline and no axis the product needs. */
function Trend({ points }: { points: History["points"] }) {
  if (points.length < 2) return <p className="m-0 text-sm text-fg-muted">The trend appears with the second report that has a check count.</p>;
  const w = 600;
  const h = 120;
  const x = (i: number) => (i / (points.length - 1)) * (w - 20) + 10;
  const y = (v: number) => h - 10 - (v / 100) * (h - 20);
  const first = points[0]!;
  const last = points[points.length - 1]!;
  return (
    <figure className="m-0">
      <svg viewBox={`0 0 ${w} ${h}`} role="img" aria-label={`Score from ${first.score}% to ${last.score}% over ${points.length} reports`} className="h-32 w-full text-accent">
        <line x1="10" x2={w - 10} y1={y(100)} y2={y(100)} stroke="currentColor" strokeOpacity="0.15" />
        <line x1="10" x2={w - 10} y1={y(0)} y2={y(0)} stroke="currentColor" strokeOpacity="0.15" />
        <polyline fill="none" stroke="currentColor" strokeWidth="2" points={points.map((p, i) => `${x(i)},${y(p.score)}`).join(" ")} />
        {points.map((p, i) => (
          <circle key={`${p.at}-${i}`} cx={x(i)} cy={y(p.score)} r="3" fill="currentColor">
            <title>{`${p.score}% on ${new Date(p.at).toLocaleDateString()} (${p.engine}, ${p.passed} of ${p.total} passed)`}</title>
          </circle>
        ))}
      </svg>
      <figcaption className="text-xs text-fg-muted">
        {first.score}% on {new Date(first.at).toLocaleDateString()} to {last.score}% on {new Date(last.at).toLocaleDateString()}
      </figcaption>
    </figure>
  );
}

function TargetsPage({ call, reload }: { call: Call; reload: () => void }) {
  const { can } = useAuth();
  const [rows, setRows] = useState<Target[]>();
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<Kind>("kubernetes");
  const [benchmark, setBenchmark] = useState("");
  const [error, setError] = useState<string>();
  const load = useCallback(() => void call<{ targets: Target[] }>("/api/v1/targets?limit=500").then((r) => setRows(r.targets), () => setRows([])), [call]);
  useEffect(load, [load]);
  const close = () => (setAdding(false), setName(""), setBenchmark(""), setError(undefined));

  const add = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const t = await call<Target>("/api/v1/targets", { method: "POST", body: JSON.stringify({ name, kind, ...(benchmark.trim() && { benchmark: benchmark.trim() }) }) });
      close();
      reload();
      navigate(`/targets/${t.id}`);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const columns: Column<Target>[] = [
    {
      id: "name",
      header: "Target",
      width: "22%",
      sortValue: (t) => t.name,
      cell: (t) => (
        <a href={`/targets/${t.id}`} className="font-medium">
          {t.name}
        </a>
      ),
    },
    { id: "kind", header: "Kind", cell: (t) => <span className="text-xs">{KIND_LABEL[t.kind]}</span> },
    { id: "benchmark", header: "Benchmark", cell: (t) => <span className="text-xs">{t.benchmark ?? "–"}</span> },
    { id: "score", header: "Score", sortValue: (t) => t.score ?? -1, cell: (t) => <ScoreBadge score={t.score} /> },
    { id: "open", header: "Failing", cell: (t) => <SevCounts counts={t.open} /> },
    { id: "check", header: "Check", cell: (t) => (t.lastScan ? <CheckStatus passed={t.lastScan.passed} /> : "–") },
  ];
  return (
    <>
      <PageHeader
        title="Targets"
        description="A cloud account, a Kubernetes cluster or a group of hosts whose configuration is judged against a benchmark."
        actions={
          can("admin") && (
            <Button variant="primary" icon={<Plus />} onClick={() => setAdding(true)}>
              Add target
            </Button>
          )
        }
      />
      <Panel flush>
        <DataTable
          label="Targets"
          columns={columns}
          rows={rows ?? []}
          loading={!rows}
          getRowId={(t) => t.id}
          minWidth={820}
          empty={<EmptyState title="No targets yet">{can("admin") ? "Add the cluster, account or hosts you check." : "An admin adds what is checked."}</EmptyState>}
        />
      </Panel>
      <Dialog
        open={adding}
        onOpenChange={(open) => !open && close()}
        title="Add a target"
        description="Reports are sent for it by name."
        onSubmit={add}
        footer={
          <>
            <Button type="button" onClick={close}>
              Cancel
            </Button>
            <Button type="submit" variant="primary" disabled={!name.trim()}>
              Add target
            </Button>
          </>
        }
      >
        <TextField label="Name" value={name} onChange={(e) => setName(e.target.value)} hint="Letters, digits, . _ and -. CI sends reports by this name." error={error} />
        <SelectField label="Kind" value={kind} onChange={(e) => setKind(e.target.value as Kind)} options={(Object.keys(KIND_LABEL) as Kind[]).map((k) => ({ value: k, label: KIND_LABEL[k] }))} />
        <TextField label="Benchmark" value={benchmark} onChange={(e) => setBenchmark(e.target.value)} hint="Optional, such as CIS Kubernetes 1.9." />
      </Dialog>
    </>
  );
}

function TargetPage({ call, id, reload }: { call: Call; id: string; reload: () => void }) {
  const { can } = useAuth();
  const [target, setTarget] = useState<Target | null>();
  const [scans, setScans] = useState<Scan[]>();
  const [history, setHistory] = useState<History>();
  const [failOn, setFailOn] = useState<FailOn>("high");
  const [benchmark, setBenchmark] = useState("");
  const [error, setError] = useState<string>();
  const [removing, setRemoving] = useState(false);

  const load = useCallback(() => {
    call<Target>(`/api/v1/targets/${id}`).then((t) => (setTarget(t), setFailOn(t.failOn), setBenchmark(t.benchmark ?? "")), () => setTarget(null));
    call<{ scans: Scan[] }>(`/api/v1/targets/${id}/scans?limit=50`).then((r) => setScans(r.scans), () => setScans([]));
    call<History>(`/api/v1/targets/${id}/history`).then(setHistory, () => {});
  }, [call, id]);
  useEffect(load, [load]);

  const save = async () => {
    try {
      await call(`/api/v1/targets/${id}`, { method: "PATCH", body: JSON.stringify({ failOn, benchmark: benchmark.trim() || null }) });
      setError(undefined);
      load();
      reload();
    } catch (err) {
      setError((err as Error).message);
    }
  };
  const remove = () =>
    call(`/api/v1/targets/${id}`, { method: "DELETE" }).then(
      () => {
        reload();
        navigate("/targets");
      },
      (err: Error) => setError(err.message),
    );

  if (target === null)
    return (
      <EmptyState title="Target not found">
        It may have been deleted. <a href="/targets">Back to targets</a>.
      </EmptyState>
    );

  const columns: Column<Scan>[] = [
    { id: "when", header: "Report", sortValue: (s) => s.createdAt, cell: (s) => <span className="text-xs whitespace-nowrap">{ago(s.createdAt)}</span> },
    { id: "engine", header: "Engine", cell: (s) => <Badge>{s.engine}</Badge> },
    { id: "score", header: "Score", cell: (s) => <ScoreBadge score={s.score} /> },
    { id: "total", header: "Failing", align: "right", cell: (s) => s.total },
    { id: "new", header: "New", align: "right", cell: (s) => s.new },
    { id: "fixed", header: "Fixed", align: "right", cell: (s) => s.resolved },
    { id: "check", header: "Check", cell: (s) => <CheckStatus passed={s.passed} /> },
  ];
  return (
    <>
      <PageHeader
        title={target?.name ?? "Target"}
        description={target ? `${KIND_LABEL[target.kind]}${target.benchmark ? ` · ${target.benchmark}` : ""} · ${plural(Object.values(target.open).reduce((a, b) => a + b, 0), "failing control")}` : undefined}
        actions={target && <ScoreBadge score={target.score} />}
      />
      <Panel title="Score over time" description="The share of checks that passed in each report that gave a count.">
        {history ? <Trend points={history.points} /> : <p className="m-0 text-sm text-fg-muted">Loading…</p>}
      </Panel>
      {can("admin") && target && (
        <Panel title="Policy" description="What a check treats as a failure. Only failed controls an engine did not report before, and nobody has decided about, can fail it.">
          <div className="grid gap-2 sm:grid-cols-2">
            <SelectField label="Fail the check for" value={failOn} onChange={(e) => setFailOn(e.target.value as FailOn)} options={FAIL_ON} />
            <TextField label="Benchmark" value={benchmark} onChange={(e) => setBenchmark(e.target.value)} hint="A label, such as CIS Kubernetes 1.9." error={error} />
          </div>
          <div className="mt-3 flex gap-2">
            <Button variant="primary" onClick={() => void save()} disabled={failOn === target.failOn && benchmark.trim() === (target.benchmark ?? "")}>
              Save policy
            </Button>
            <Button icon={<Trash2 />} onClick={() => setRemoving(true)}>
              Delete target
            </Button>
          </div>
          <Dialog
            open={removing}
            onOpenChange={setRemoving}
            title={`Delete ${target.name}?`}
            description="Its reports, findings and decisions are deleted. A later report needs the target added again."
            footer={
              <>
                <Button type="button" onClick={() => setRemoving(false)}>
                  Cancel
                </Button>
                <Button type="button" variant="primary" onClick={() => void remove()}>
                  Delete
                </Button>
              </>
            }
          >
            <></>
          </Dialog>
        </Panel>
      )}
      <FindingsTable call={call} targetId={id} summary={target ?? undefined} reload={() => (load(), reload())} />
      <Panel title="Reports" flush>
        <DataTable label="Reports" columns={columns} rows={scans ?? []} loading={!scans} getRowId={(s) => s.id} minWidth={720} empty={<EmptyState title="No reports">Nothing has been sent for this target.</EmptyState>} />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Setup

function SetupPage() {
  const origin = window.location.origin;
  return (
    <>
      <PageHeader title="Setup" description="Run Trivy, kubescape, checkov or Prowler against what you check, and send the report here. The answer says whether the check passes." />
      <Panel title="Send a report" description="Add the target first. Use POSTURE_INGEST_TOKEN, set where posture runs, or an API token with the editor role from API tokens.">
        <Code>{`trivy config --format sarif -o results.sarif .
curl -sf -X POST -H "Authorization: Bearer $POSTURE_INGEST_TOKEN" -H 'content-type: application/json' \\
  --data-binary @results.sarif \\
  "${origin}/api/v1/scans?target=prod-cluster" > scan.json
jq -e '.passed' scan.json   # fail the pipeline`}</Code>
      </Panel>
      <Panel title="How a report is compared" description="Each engine's reports replace its own earlier ones. A control that stops failing is fixed; one that fails for the first time is new.">
        <ul className="posture-list flex flex-col gap-1 text-sm text-fg-muted">
          <li>The first report of an engine for a target adopts what is there and never fails a check.</li>
          <li>A failed control is found again by rule and resource.</li>
          <li>The score is the share of checks that passed: from the report's own summary (run property summary with passed, failed and total), or from its results of kind pass.</li>
          <li>Benchmark, control and section are kept when the report has them (properties benchmark, control, section), so findings can be filtered by them.</li>
          <li>A compensating control, a false positive or an accepted risk stays with the finding, with a reason.</li>
        </ul>
      </Panel>
    </>
  );
}

/** The first screen, until the first target exists. The summary is polled, so it gives way by itself. */
function WelcomePage() {
  return (
    <>
      <PageHeader title="Get started" description="Add what you check, and send a report." actions={<StatusBadge tone="info">Waiting for the first target</StatusBadge>} />
      <SetupPage />
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title="Admins only">Ask an admin of this posture for access.</EmptyState>;
  const titles = {
    account: ["Account", "Your profile, password, two-step verification and where you are signed in."],
    members: ["Members", "Who can sign in to this posture, and with which role. Viewers see everything; editors also decide about findings; admins also add, change and delete targets, and manage members and tokens."],
    signin: ["Sign-in", "Identity providers people can sign in with, such as OpenAsy Identity, Keycloak or Microsoft Entra ID, and which of their groups give which role."],
    tokens: ["API tokens", "For scripts and CI. Each token has one role and an expiry; the secret is shown once."],
  } as const;
  return (
    <>
      <PageHeader
        title={titles[page][0]}
        description={titles[page][1]}
        actions={
          page === "account" && (
            <Button icon={<LogOut />} onClick={() => void signOut()}>
              Sign out
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
  const [theme, setTheme] = useThemePreference();
  const { me, can } = useAuth();
  const route = parseRoute(usePath());
  const [summary, setSummary] = useState<Summary>();
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);
  const call = useApi();

  // The install's other products (OPENASY_PRODUCTS), for the switcher; ids this UI does not know are left out.
  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) => setProducts(r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "posture" && (PRODUCT_IDS as readonly string[]).includes(p.id))),
      () => {},
    );
  }, [call]);

  const reload = useCallback(() => void call<Summary>("/api/v1/summary").then(setSummary, () => {}), [call]);
  useEffect(() => {
    reload();
    const t = setInterval(reload, 15_000);
    return () => clearInterval(t);
  }, [reload]);

  const nav = [
    { id: "findings", label: "Findings", icon: Bug },
    { id: "targets", label: "Targets", icon: Crosshair, count: summary?.targets },
  ];
  const footerNav = [
    { id: "setup", label: "Setup", icon: Settings2 },
    ...(can("admin")
      ? [
          { id: "members", label: "Members", icon: Users },
          { id: "signin", label: "Sign-in", icon: LogIn },
          { id: "tokens", label: "API tokens", icon: KeyRound },
        ]
      : []),
    { id: "account", label: "Account", icon: UserRound },
  ];
  const active = route.page === "target" ? "targets" : route.page;
  const roleName = me.user.role.charAt(0).toUpperCase() + me.user.role.slice(1);

  return (
    <AppShell
      product="posture"
      nav={nav}
      activeNav={active}
      onNavigate={(id) => navigate(`/${id}`)}
      connectedProducts={products.map((p) => p.id)}
      onSwitchProduct={(id) => {
        const to = products.find((p) => p.id === id);
        if (to) window.location.assign(to.url);
      }}
      footerNav={footerNav}
      user={{ name: me.user.name, role: roleName }}
      theme={theme}
      onThemeChange={setTheme}
    >
      {route.page === "findings" && summary && summary.targets === 0 ? (
        <WelcomePage />
      ) : route.page === "findings" ? (
        <FindingsPage call={call} summary={summary} reload={reload} />
      ) : route.page === "targets" ? (
        <TargetsPage call={call} reload={reload} />
      ) : route.page === "target" ? (
        <TargetPage key={route.id} call={call} id={route.id} reload={reload} />
      ) : route.page === "account" || route.page === "members" || route.page === "signin" || route.page === "tokens" ? (
        <SettingsPage page={route.page} />
      ) : (
        <SetupPage />
      )}
    </AppShell>
  );
}

export function App() {
  const [theme] = useThemePreference();
  return (
    // No organization until branding is configurable (ADR 0004); the library's default is a placeholder.
    <BrandProvider theme={theme} brand={{ name: "OpenAsy", organization: undefined }} className="min-h-screen">
      <AuthGate product="OpenAsy Posture">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
