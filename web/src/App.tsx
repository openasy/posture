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
  TimeSeriesChart,
  usePath,
  type Column,
  type ProductId,
  useThemePreference,
  useAgo,
  toLocale,
  useLocalePreference,
} from "@openasy/ui";
import { AccountSettings, AuthGate, MembersSettings, SignInSettings, TokensSettings, useAccountMenu, useAuth, useInstallBrand } from "@openasy/auth/react";
import colophon from "virtual:openasy-colophon";
import { Bug, CircleSlash, Crosshair, KeyRound, LogIn, LogOut, Plus, Trash2, UserRound, Users, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import {
  api,
  MfaSetupRequired,
  Unauthorized,
  type FailOn,
  type Finding,
  type History,
  type Kind,
  type ProductLink,
  type Scan,
  type Severity,
  type HostsCoverage,
  type Summary,
  type Target,
} from "./api.ts";
import { useT, type T } from "./i18n.ts";
import { search } from "./search.ts";

const PAGES = ["targets", "setup", "account", "members", "signin", "tokens", "about"] as const;
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
const FAIL_ON = (t: T): Array<{ value: FailOn; label: string }> => [
  { value: "critical", label: t("failOn.critical") },
  { value: "high", label: t("failOn.highOrWorse") },
  { value: "medium", label: t("failOn.mediumOrWorse") },
  { value: "low", label: t("failOn.anyFinding") },
  { value: "none", label: t("failOn.neverFail") },
];

/** Compact severity counts; each badge carries the full name for screen readers. */
function SevCounts({ counts }: { counts: Record<Severity, number> }) {
  const t = useT();
  const shown = SEVERITIES.filter((s) => counts[s] > 0);
  if (!shown.length) return <span className="text-xs text-fg-muted">{t("sevCounts.none")}</span>;
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
  const ago = useAgo();
  const msg = useT();
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
      await call(url, {
        method: "PUT",
        body: JSON.stringify({ state, reason, ...(state === "accepted" && { expiresAt: new Date(Date.now() + Number(days) * 86_400_000).toISOString() }) }),
      });
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
      aria-label={msg("findingPanel.details", { rule: finding.rule })}
      title={<span className="posture-wrap font-mono text-sm">{finding.rule}</span>}
      description={`${finding.target.name} · ${finding.engine}`}
      actions={
        <IconButton label={msg("findingPanel.closeDetails")} size="sm" onClick={onClose}>
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
              <StatusBadge tone={t.active ? "success" : "neutral"}>
                {t.state === "compensating"
                  ? msg("findingPanel.compensatingControl")
                  : t.state === "false-positive"
                    ? msg("findingPanel.falsePositive")
                    : t.active
                      ? msg("findingPanel.acceptedRisk")
                      : msg("findingPanel.acceptanceExpired")}
              </StatusBadge>
            </span>
            <span>{t.reason}</span>
            <span className="text-fg-muted">
              {t.by ? `${t.by}, ` : ""}
              {ago(t.at)}
              {t.expiresAt ? msg("findingPanel.until", { value: new Date(t.expiresAt).toLocaleDateString() }) : ""}
            </span>
          </div>
        )}
        {can("editor") && (
          <div className="flex gap-2 border-t border-line pt-3">
            <Button size="sm" icon={<CircleSlash />} onClick={() => setDeciding(true)}>
              {t ? msg("findingPanel.changeDecision") : msg("findingPanel.triage")}
            </Button>
            {t && (
              <Button size="sm" onClick={() => void reopen()}>
                {msg("findingPanel.openAgain")}
              </Button>
            )}
          </div>
        )}
        <Dialog
          open={deciding}
          onOpenChange={(open) => !open && close()}
          title={msg("findingPanel.triage2", { rule: finding.rule })}
          description={msg("findingPanel.theDecisionStaysWithThis")}
          onSubmit={decide}
          footer={
            <>
              <Button type="button" onClick={close}>
                {msg("findingPanel.cancel")}
              </Button>
              <Button type="submit" variant="primary" disabled={reason.trim().length < 3}>
                {msg("findingPanel.saveDecision")}
              </Button>
            </>
          }
        >
          <SelectField
            label={msg("findingPanel.decision")}
            value={state}
            onChange={(e) => setState(e.target.value as typeof state)}
            options={[
              { value: "compensating", label: msg("findingPanel.compensatingControlSomethingElseCovers") },
              { value: "false-positive", label: msg("findingPanel.falsePositive") },
              { value: "accepted", label: msg("findingPanel.acceptedRisk") },
            ]}
          />
          <TextField
            label={msg("findingPanel.reason")}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            hint={msg("findingPanel.whyForTheNextReview")}
            error={error}
          />
          {state === "accepted" && (
            <SelectField
              label={msg("findingPanel.for")}
              value={days}
              onChange={(e) => setDays(e.target.value)}
              options={[
                { value: "30", label: msg("findingPanel.n30Days") },
                { value: "90", label: msg("findingPanel.n90Days") },
                { value: "180", label: msg("findingPanel.n180Days") },
                { value: "365", label: msg("findingPanel.n1Year") },
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
function FindingsTable({
  call,
  targetId,
  summary,
  reload,
}: {
  call: Call;
  targetId?: string;
  summary?: { open: Record<Severity, number> };
  reload: () => void;
}) {
  const ago = useAgo();
  const t = useT();
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
    query().then(
      (r) => (setRows(r.findings), setMore(r.nextCursor)),
      () => setRows([]),
    );
  }, [query]);
  useEffect(load, [load]);
  useEffect(() => void call<{ benchmarks: string[]; sections: string[] }>("/api/v1/facets").then(setFacets, () => {}), [call]);
  const loadMore = () => more && query(more).then((r) => (setRows((x) => [...(x ?? []), ...r.findings]), setMore(r.nextCursor)));

  const columns: Column<Finding>[] = [
    { id: "sev", header: t("findingsTable.severity"), width: "104px", cell: (f) => <SeverityBadge severity={f.severity} /> },
    {
      id: "rule",
      header: t("findingsTable.rule"),
      width: "30%",
      cell: (f) => (
        <span className="flex min-w-0 flex-col">
          <button type="button" onClick={() => setOpen(f)} className="posture-wrap self-start text-left font-mono text-xs font-medium text-fg hover:underline">
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
      header: t("findingsTable.resource"),
      width: "32%",
      cell: (f) => (
        <span className="posture-wrap font-mono text-xs">
          {f.resource}
          {f.control ? <span className="text-fg-muted"> · {f.control}</span> : null}
        </span>
      ),
    },
    { id: "engine", header: t("findingsTable.engine"), cell: (f) => <Badge>{f.engine}</Badge> },
    ...(targetId
      ? []
      : [
          { id: "target", header: t("findingsTable.target"), cell: (f: Finding) => <span className="text-xs">{f.target.name}</span> } satisfies Column<Finding>,
        ]),
    {
      id: "seen",
      header: t("findingsTable.firstSeen"),
      sortValue: (f) => f.firstSeen,
      cell: (f) => <span className="text-xs whitespace-nowrap">{ago(f.firstSeen)}</span>,
    },
  ];

  return (
    <>
      <Tabs<Tab>
        label={t("findingsTable.findingViews")}
        value={tab}
        onChange={setTab}
        items={[
          { value: "open", label: t("findingsTable.open") },
          { value: "suppressed", label: t("findingsTable.decided") },
          { value: "resolved", label: t("findingsTable.fixed") },
        ]}
      />
      <FilterBar onClear={() => (setSev([]), setQ(""), setBenchmark([]), setSection([]))}>
        <FacetFilter
          label={t("findingsTable.severity")}
          selected={sev}
          onChange={setSev}
          options={SEVERITIES.map((s) => ({ value: s, label: s.charAt(0).toUpperCase() + s.slice(1), count: tab === "open" ? summary?.open[s] : undefined }))}
        />
        {facets.benchmarks.length > 0 && (
          <FacetFilter
            label={t("findingsTable.benchmark")}
            selected={benchmark}
            onChange={(v) => setBenchmark(v.slice(-1))}
            options={facets.benchmarks.map((b) => ({ value: b, label: b }))}
          />
        )}
        {facets.sections.length > 0 && (
          <FacetFilter
            label={t("findingsTable.section")}
            selected={section}
            onChange={(v) => setSection(v.slice(-1))}
            options={facets.sections.map((b) => ({ value: b, label: b }))}
          />
        )}
        <SearchInput label={t("findingsTable.searchRuleControlResourceOr")} className="w-64" value={q} onChange={(e) => setQ(e.target.value)} />
      </FilterBar>
      <div className={open ? "grid gap-2.5 xl:grid-cols-[minmax(0,2fr)_minmax(320px,1fr)]" : "grid gap-2.5"}>
        <Panel
          title={tab === "open" ? t("findingsTable.open") : tab === "suppressed" ? t("findingsTable.decided") : t("findingsTable.fixed")}
          description={t("findingsTable.controlsThatFailMostSevere")}
          flush
          footer={
            more ? (
              <Button size="sm" onClick={loadMore}>
                {t("findingsTable.loadMore")}
              </Button>
            ) : undefined
          }
        >
          <DataTable
            label={t("findingsTable.findings")}
            columns={columns}
            rows={rows ?? []}
            loading={!rows}
            getRowId={(f) => `${f.target.id}/${f.fingerprint}`}
            onRowClick={(f) => setOpen(f)}
            activeRowId={open ? `${open.target.id}/${open.fingerprint}` : undefined}
            minWidth={900}
            pageSize={50}
            empty={
              <EmptyState
                title={
                  tab === "open"
                    ? t("findingsTable.noOpenFindings")
                    : tab === "suppressed"
                      ? t("findingsTable.nothingTriaged")
                      : t("findingsTable.nothingFixedYet")
                }
              >
                {tab === "open" && summary && !Object.values(summary.open).some(Boolean) ? (
                  <>
                    {t("findingsTable.sendAReportToSee")} <a href="/setup">{t("findingsTable.setup")}</a>.
                  </>
                ) : (
                  t("findingsTable.nothingMatchesTheseFilters")
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
  const t = useT();
  if (!file) return null;
  if (file.error) {
    return (
      <Callout tone="danger" title={t("hostsCoverageNote.theHostsFileIsNot")}>
        {t("hostsCoverageNote.itsLastGoodVersionIs", { error: file.error, path: file.path })}
      </Callout>
    );
  }
  if (!file.missing.length) return null;
  return (
    <Callout tone="warning" title={t("hostsCoverageNote.inTheHostsFileNo", { count: file.missing.length })}>
      {file.missing.map((h) => h.name).join(", ")}. {t("hostsCoverageNote.whatToDo")}
    </Callout>
  );
}

function FindingsPage({ call, summary, reload }: { call: Call; summary?: Summary; reload: () => void }) {
  const ago = useAgo();
  const t = useT();
  const s = summary;
  return (
    <>
      <PageHeader
        title={t("findingsPage.findings")}
        description={s ? t("findingsPage.lastReport", { plural: t("plurals.target", { count: s.targets }), ago: ago(s.lastScanAt) }) : undefined}
      />
      <HostsCoverageNote file={s?.hostsFile} />
      {s && (
        <KpiGrid minWidth={150}>
          <KpiCard
            label={t("findingsPage.averageScore")}
            value={s.averageScore === null ? "–" : `${s.averageScore}%`}
            tone={s.averageScore === null ? "info" : s.averageScore >= 90 ? "success" : s.averageScore >= 70 ? "warning" : "danger"}
          />
          <KpiCard label={t("findingsPage.critical")} value={s.open.critical} footer={<SeverityBadge severity="critical" />} />
          <KpiCard label={t("findingsPage.high")} value={s.open.high} footer={<SeverityBadge severity="high" />} />
          <KpiCard label={t("findingsPage.medium")} value={s.open.medium} footer={<SeverityBadge severity="medium" />} />
          <KpiCard label={t("findingsPage.low")} value={s.open.low} footer={<SeverityBadge severity="low" />} />
          <KpiCard label={t("findingsPage.failedChecks7Days")} value={s.failingChecks} tone={s.failingChecks ? "warning" : "success"} />
        </KpiGrid>
      )}
      <FindingsTable call={call} summary={s} reload={reload} />
    </>
  );
}

function CheckStatus({ passed }: { passed: boolean }) {
  const t = useT();
  return passed ? <StatusBadge tone="success">{t("checkStatus.passed")}</StatusBadge> : <StatusBadge tone="danger">{t("checkStatus.failed")}</StatusBadge>;
}

const KIND_LABEL = (t: T): Record<Kind, string> => ({ cloud: t("kindLabel.cloudAccount"), kubernetes: t("kindLabel.kubernetesCluster"), host: "Hosts" });

function ScoreBadge({ score }: { score: number | null }) {
  const t = useT();
  if (score === null) return <span className="text-xs text-fg-muted">{t("scoreBadge.noScore")}</span>;
  return <StatusBadge tone={score >= 90 ? "success" : score >= 70 ? "warning" : "danger"}>{score}%</StatusBadge>;
}

/** The score of each engine as a line, oldest report first: an engine keeps its last score until it reports again. */
function Trend({ points }: { points: History["points"] }) {
  const t = useT();
  const engines = [...new Set(points.map((p) => p.engine))];
  const last = new Map<string, number>();
  const rows = points.map((p) => (last.set(p.engine, p.score), engines.map((e) => last.get(e))));
  // The line starts once every engine has a score, so none is drawn as 0 before its first report.
  const from = rows.findIndex((r) => r.every((v) => v !== undefined));
  if (from < 0 || points.length - from < 2) return <p className="m-0 text-sm text-fg-muted">{t("trend.theTrendAppearsWithThe")}</p>;
  return (
    <TimeSeriesChart
      label={t("trend.scoreOfEachEngineOver", { length: points.length - from })}
      series={engines.map((e, i) => ({ id: e, name: e, data: rows.slice(from).map((r) => r[i]!) }))}
      labels={points.slice(from).map((p) => new Date(p.at).toLocaleDateString())}
      yMax={100}
      format={(v) => `${v}%`}
      area={false}
      height={160}
    />
  );
}

function TargetsPage({ call, reload }: { call: Call; reload: () => void }) {
  const msg = useT();
  const { can } = useAuth();
  const [rows, setRows] = useState<Target[]>();
  const [adding, setAdding] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState<Kind>("kubernetes");
  const [benchmark, setBenchmark] = useState("");
  const [error, setError] = useState<string>();
  const load = useCallback(
    () =>
      void call<{ targets: Target[] }>("/api/v1/targets?limit=500").then(
        (r) => setRows(r.targets),
        () => setRows([]),
      ),
    [call],
  );
  useEffect(load, [load]);
  const close = () => (setAdding(false), setName(""), setBenchmark(""), setError(undefined));

  const add = async (e: FormEvent) => {
    e.preventDefault();
    try {
      const t = await call<Target>("/api/v1/targets", {
        method: "POST",
        body: JSON.stringify({ name, kind, ...(benchmark.trim() && { benchmark: benchmark.trim() }) }),
      });
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
      header: msg("targetsPage.target"),
      width: "22%",
      sortValue: (t) => t.name,
      cell: (t) => (
        <a href={`/targets/${t.id}`} className="font-medium">
          {t.name}
        </a>
      ),
    },
    { id: "kind", header: msg("targetsPage.kind"), cell: (t) => <span className="text-xs">{KIND_LABEL(msg)[t.kind]}</span> },
    { id: "benchmark", header: msg("targetsPage.benchmark"), cell: (t) => <span className="text-xs">{t.benchmark ?? "–"}</span> },
    { id: "score", header: msg("targetsPage.score"), sortValue: (t) => t.score ?? -1, cell: (t) => <ScoreBadge score={t.score} /> },
    { id: "open", header: msg("targetsPage.failing"), cell: (t) => <SevCounts counts={t.open} /> },
    { id: "check", header: msg("targetsPage.check"), cell: (t) => (t.lastScan ? <CheckStatus passed={t.lastScan.passed} /> : "–") },
  ];
  return (
    <>
      <PageHeader
        title={msg("targetsPage.targets")}
        description={msg("targetsPage.aCloudAccountAKubernetes")}
        actions={
          can("admin") && (
            <Button variant="primary" icon={<Plus />} onClick={() => setAdding(true)}>
              {msg("targetsPage.addTarget")}
            </Button>
          )
        }
      />
      <Panel flush>
        <DataTable
          label={msg("targetsPage.targets")}
          columns={columns}
          rows={rows ?? []}
          loading={!rows}
          getRowId={(t) => t.id}
          minWidth={820}
          empty={
            <EmptyState title={msg("targetsPage.noTargetsYet")}>
              {can("admin") ? msg("targetsPage.addTheClusterAccountOr") : msg("targetsPage.anAdminAddsWhatIs")}
            </EmptyState>
          }
        />
      </Panel>
      <Dialog
        open={adding}
        onOpenChange={(open) => !open && close()}
        title={msg("targetsPage.addATarget")}
        description={msg("targetsPage.reportsAreSentForIt")}
        onSubmit={add}
        footer={
          <>
            <Button type="button" onClick={close}>
              {msg("targetsPage.cancel")}
            </Button>
            <Button type="submit" variant="primary" disabled={!name.trim()}>
              {msg("targetsPage.addTarget")}
            </Button>
          </>
        }
      >
        <TextField
          label={msg("targetsPage.name")}
          value={name}
          onChange={(e) => setName(e.target.value)}
          hint={msg("targetsPage.lettersDigitsAndCiSends")}
          error={error}
        />
        <SelectField
          label={msg("targetsPage.kind")}
          value={kind}
          onChange={(e) => setKind(e.target.value as Kind)}
          options={(Object.keys(KIND_LABEL(msg)) as Kind[]).map((k) => ({ value: k, label: KIND_LABEL(msg)[k] }))}
        />
        <TextField
          label={msg("targetsPage.benchmark")}
          value={benchmark}
          onChange={(e) => setBenchmark(e.target.value)}
          hint={msg("targetsPage.optionalSuchAsCisKubernetes")}
        />
      </Dialog>
    </>
  );
}

function TargetPage({ call, id, reload }: { call: Call; id: string; reload: () => void }) {
  const ago = useAgo();
  const msg = useT();
  const { can } = useAuth();
  const [target, setTarget] = useState<Target | null>();
  const [scans, setScans] = useState<Scan[]>();
  const [history, setHistory] = useState<History>();
  const [failOn, setFailOn] = useState<FailOn>("high");
  const [benchmark, setBenchmark] = useState("");
  const [error, setError] = useState<string>();
  const [removing, setRemoving] = useState(false);

  const load = useCallback(() => {
    call<Target>(`/api/v1/targets/${id}`).then(
      (t) => (setTarget(t), setFailOn(t.failOn), setBenchmark(t.benchmark ?? "")),
      () => setTarget(null),
    );
    call<{ scans: Scan[] }>(`/api/v1/targets/${id}/scans?limit=50`).then(
      (r) => setScans(r.scans),
      () => setScans([]),
    );
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
      <EmptyState title={msg("targetPage.targetNotFound")}>
        {msg("targetPage.itMayHaveBeenDeleted")} <a href="/targets">{msg("targetPage.backToTargets")}</a>.
      </EmptyState>
    );

  const columns: Column<Scan>[] = [
    {
      id: "when",
      header: msg("targetPage.report"),
      sortValue: (s) => s.createdAt,
      cell: (s) => <span className="text-xs whitespace-nowrap">{ago(s.createdAt)}</span>,
    },
    { id: "engine", header: msg("targetPage.engine"), cell: (s) => <Badge>{s.engine}</Badge> },
    { id: "score", header: msg("targetPage.score"), cell: (s) => <ScoreBadge score={s.score} /> },
    { id: "total", header: msg("targetPage.failing"), align: "right", cell: (s) => s.total },
    { id: "new", header: msg("targetPage.new"), align: "right", cell: (s) => s.new },
    { id: "fixed", header: msg("targetPage.fixed"), align: "right", cell: (s) => s.resolved },
    { id: "check", header: msg("targetPage.check"), cell: (s) => <CheckStatus passed={s.passed} /> },
  ];
  return (
    <>
      <PageHeader
        title={target?.name ?? msg("targetPage.target")}
        description={
          target
            ? `${KIND_LABEL(msg)[target.kind]}${target.benchmark ? ` · ${target.benchmark}` : ""} · ${msg("plurals.failingControl", { count: Object.values(target.open).reduce((a, b) => a + b, 0) })}`
            : undefined
        }
        actions={target && <ScoreBadge score={target.score} />}
      />
      <Panel title={msg("targetPage.scoreOverTime")} description={msg("targetPage.theShareOfChecksThat")}>
        {history ? <Trend points={history.points} /> : <p className="m-0 text-sm text-fg-muted">{msg("common.loading")}</p>}
      </Panel>
      {can("admin") && target && (
        <Panel title={msg("targetPage.policy")} description={msg("targetPage.whatACheckTreatsAs")}>
          <div className="grid gap-2 sm:grid-cols-2">
            <SelectField
              label={msg("targetPage.failTheCheckFor")}
              value={failOn}
              onChange={(e) => setFailOn(e.target.value as FailOn)}
              options={FAIL_ON(msg)}
            />
            <TextField
              label={msg("targetPage.benchmark")}
              value={benchmark}
              onChange={(e) => setBenchmark(e.target.value)}
              hint={msg("targetPage.aLabelSuchAsCis")}
              error={error}
            />
          </div>
          <div className="mt-3 flex gap-2">
            <Button variant="primary" onClick={() => void save()} disabled={failOn === target.failOn && benchmark.trim() === (target.benchmark ?? "")}>
              {msg("targetPage.savePolicy")}
            </Button>
            <Button icon={<Trash2 />} onClick={() => setRemoving(true)}>
              {msg("targetPage.deleteTarget")}
            </Button>
          </div>
          <Dialog
            open={removing}
            onOpenChange={setRemoving}
            title={msg("targetPage.delete", { name: target.name })}
            description={msg("targetPage.itsReportsFindingsAndDecisions")}
            footer={
              <>
                <Button type="button" onClick={() => setRemoving(false)}>
                  {msg("targetPage.cancel")}
                </Button>
                <Button type="button" variant="primary" onClick={() => void remove()}>
                  {msg("targetPage.delete2")}
                </Button>
              </>
            }
          >
            <></>
          </Dialog>
        </Panel>
      )}
      <FindingsTable call={call} targetId={id} summary={target ?? undefined} reload={() => (load(), reload())} />
      <Panel title={msg("targetPage.reports")} flush>
        <DataTable
          label={msg("targetPage.reports")}
          columns={columns}
          rows={scans ?? []}
          loading={!scans}
          getRowId={(s) => s.id}
          minWidth={720}
          empty={<EmptyState title={msg("targetPage.noReports")}>{msg("targetPage.nothingHasBeenSentFor")}</EmptyState>}
        />
      </Panel>
    </>
  );
}

// ---------------------------------------------------------------- Setup

function SetupPage() {
  const t = useT();
  const origin = window.location.origin;
  return (
    <>
      <PageHeader title={t("setupPage.setup")} description={t("setupPage.runTrivyKubescapeCheckovOr")} />
      <Panel title={t("setupPage.sendAReport")} description={t("setupPage.addTheTargetFirstUse")}>
        <Code>{`trivy config --format sarif -o results.sarif .
curl -sf -X POST -H "Authorization: Bearer $POSTURE_INGEST_TOKEN" -H 'content-type: application/json' \\
  --data-binary @results.sarif \\
  "${origin}/api/v1/scans?target=prod-cluster" > scan.json
jq -e '.passed' scan.json   # fail the pipeline`}</Code>
      </Panel>
      <Panel title={t("setupPage.howAReportIsCompared")} description={t("setupPage.eachEngineSReportsReplace")}>
        <ul className="posture-list flex flex-col gap-1 text-sm text-fg-muted">
          <li>{t("setupPage.theFirstReportOfAn")}</li>
          <li>{t("setupPage.aFailedControlIsFound")}</li>
          <li>{t("setupPage.theScoreIsTheShare")}</li>
          <li>{t("setupPage.benchmarkControlAndSectionAre")}</li>
          <li>{t("setupPage.aCompensatingControlAFalse")}</li>
        </ul>
      </Panel>
    </>
  );
}

/** The first screen, until the first target exists. The summary is polled, so it gives way by itself. */
function WelcomePage() {
  const t = useT();
  return (
    <>
      <PageHeader
        title={t("welcomePage.getStarted")}
        description={t("welcomePage.addWhatYouCheckAnd")}
        actions={<StatusBadge tone="info">{t("welcomePage.waitingForTheFirstTarget")}</StatusBadge>}
      />
      <SetupPage />
    </>
  );
}

// ---------------------------------------------------------------- Shell

/** Account, Members, Sign-in and API tokens: the screens come from @openasy/auth. */
function SettingsPage({ page }: { page: "account" | "members" | "signin" | "tokens" }) {
  const t = useT();
  const { signOut, can } = useAuth();
  if (page !== "account" && !can("admin")) return <EmptyState title={t("settingsPage.adminsOnly")}>{t("settingsPage.askAnAdminOfThis")}</EmptyState>;
  const titles = {
    account: ["Account", "Your profile, password, two-step verification and where you are signed in."],
    members: [
      "Members",
      "Who can sign in to this posture, and with which role. Viewers see everything; editors also decide about findings; admins also add, change and delete targets, and manage members and tokens.",
    ],
    signin: [
      "Sign-in",
      "Identity providers people can sign in with, such as OpenAsy Identity, Keycloak or Microsoft Entra ID, and which of their groups give which role.",
    ],
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
              {t("settingsPage.signOut")}
            </Button>
          )
        }
      />
      {page === "account" ? <AccountSettings /> : page === "members" ? <MembersSettings /> : page === "signin" ? <SignInSettings /> : <TokensSettings />}
    </>
  );
}

function Product() {
  const msg = useT();
  const [theme, setTheme] = useThemePreference();
  const [, setLocale] = useLocalePreference();
  const { me, can } = useAuth();
  const account = useAccountMenu();
  const route = parseRoute(usePath());
  const [summary, setSummary] = useState<Summary>();
  const [products, setProducts] = useState<Array<ProductLink & { id: ProductId }>>([]);
  const call = useApi();
  const onSearch = useMemo(() => search(call, msg), [call, msg]);

  // The install's other products (OPENASY_PRODUCTS), for the switcher; ids this UI does not know are left out.
  useEffect(() => {
    void call<{ products: ProductLink[] }>("/api/v1/products").then(
      (r) =>
        setProducts(r.products.filter((p): p is ProductLink & { id: ProductId } => p.id !== "posture" && (PRODUCT_IDS as readonly string[]).includes(p.id))),
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
    { id: "findings", label: msg("product.findings"), icon: Bug },
    { id: "targets", label: msg("product.targets"), icon: Crosshair, count: summary?.targets },
  ];
  const footerNav = [
    ...(can("admin")
      ? [
          { id: "members", label: msg("product.members"), icon: Users },
          { id: "signin", label: msg("product.signIn"), icon: LogIn },
          { id: "tokens", label: msg("product.apiTokens"), icon: KeyRound },
        ]
      : []),
    { id: "account", label: msg("product.account"), icon: UserRound },
  ];
  const active = route.page === "target" ? "targets" : route.page;
  const roleName = me.user.role.charAt(0).toUpperCase() + me.user.role.slice(1);

  return (
    <AppShell
      product="posture"
      onSearch={onSearch}
      about={colophon}
      nav={nav}
      activeNav={active}
      onNavigate={(id) => navigate(`/${id}`)}
      connectedProducts={products.map((p) => p.id)}
      onSwitchProduct={(id) => {
        const to = products.find((p) => p.id === id);
        if (to) window.location.assign(to.url);
      }}
      footerNav={account.settings(footerNav)}
      setup
      user={{ name: me.user.name, role: roleName, ...account.user }}
      theme={theme}
      onThemeChange={setTheme}
      onLanguageChange={(code) => setLocale(toLocale(code))}
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
  const installBrand = useInstallBrand();
  const [theme] = useThemePreference();
  const [locale] = useLocalePreference();
  return (
    // The install's brand from config/brand.env (ADR 0053); OpenAsy's own look where it sets none.
    <BrandProvider theme={theme} locale={locale} brand={{ name: "OpenAsy", organization: undefined, ...installBrand }} className="min-h-screen">
      <AuthGate product="OpenAsy Posture">
        <Product />
      </AuthGate>
    </BrandProvider>
  );
}
