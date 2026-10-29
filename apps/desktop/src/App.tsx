import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowDownToLine,
  ArrowRight,
  Activity,
  Bot,
  Check,
  CheckCheck,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Code2,
  Database,
  FileSearch,
  FolderPlus,
  FolderOpen,
  HardDrive,
  Info,
  LayoutDashboard,
  LoaderCircle,
  LockKeyhole,
  RefreshCw,
  Search,
  ShieldCheck,
  Sparkles,
  Trash2,
  X,
} from "lucide-react";
import {
  categories,
  eligibleItems,
  formatBytes,
  selectedItems,
  totalBytes,
  type Category,
  type ScanItem,
  type ScanReport,
  type SystemInsights,
} from "@clean-my-mac/core";
import {
  pickCleanupFolder,
  previewMode,
  revealItem,
  scanSystem,
  systemInsights,
  openSystemSettings,
  trashItems,
} from "./lib/bridge";
import { Modal } from "./components/Modal";

type View = "overview" | "system" | Category;
type Filter = "all" | "eligible" | "recommended" | "review";
const MAX_SELECTION = 5_000;
const icons = {
  agents: Bot,
  caches: Database,
  developer: Code2,
  large: ArrowDownToLine,
};
const viewTitles: Record<View, string> = {
  overview: "Overview",
  agents: "Agent sessions",
  caches: "Caches & logs",
  developer: "Developer files",
  large: "Large files",
  system: "System insights",
};

function ageLabel(timestamp: number): string {
  const days = Math.max(0, Math.floor((Date.now() - timestamp) / 86_400_000));
  return days === 0 ? "Today" : `${days}d ago`;
}

function SystemInsightsPanel({
  insights, busy, error, retry, openSettings,
}: {
  insights: SystemInsights | null;
  busy: boolean;
  error: string | null;
  retry: () => void;
  openSettings: (section: "storage" | "timeMachine" | "loginItems" | "diskUtility" | "docker") => void;
}) {
  return <section className="system-insights" aria-label="System insights" aria-busy={busy}>
    <div className="insight-heading"><div><h2>System diagnostics</h2><p>Read-only checks for storage details, background services, and files held open after deletion.</p></div><button className="button secondary" onClick={retry} disabled={busy}><RefreshCw size={15} className={busy ? "spin" : ""}/> Refresh</button></div>
    {busy && <p role="status">Collecting local system details…</p>}
    {error && <div className="notice error" role="alert"><Info size={17}/><span>{error}</span><button className="button secondary" onClick={retry}>Retry</button></div>}
    {insights && <>
      <div className="insight-actions"><button className="button secondary" onClick={() => openSettings("storage")}>Open Storage settings</button><button className="button secondary" onClick={() => openSettings("timeMachine")}>Time Machine settings</button><button className="button secondary" onClick={() => openSettings("loginItems")}>Login items</button></div>
      <div className="insight-grid">
        <article className="insight-card"><h3>Local snapshots <span>{insights.snapshots.length}</span></h3><p>Snapshots can retain deleted files after Trash is emptied. macOS manages this space. Review snapshots in Disk Utility under View → Show APFS Snapshots.</p><button className="button secondary" onClick={() => openSettings("diskUtility")}>Open Disk Utility</button>{insights.snapshots.length ? insights.snapshots.map((item) => <div className="insight-row" key={`${item.volume}:${item.name}`}><strong>{item.name}</strong><small>{item.volume} · {item.purgeable === null ? "Purgeability unknown" : item.purgeable ? "Purgeable by macOS" : "Not marked purgeable"}</small></div>) : <p>No local snapshots were reported.</p>}</article>
        <article className="insight-card"><h3>Memory use <span>Top {insights.processes.length}</span></h3><p>Memory use does not mean disk use. Closing an app may release memory, but this is not a cleanup target.</p>{insights.processes.map((item) => <div className="insight-row" key={item.pid}><strong>{item.name} <small>PID {item.pid}</small></strong><small>{formatBytes(item.memoryBytes)} memory · {item.cpuPercent.toFixed(1)}% CPU</small></div>)}</article>
        <article className="insight-card"><h3>Background services <span>{insights.launchAgents.filter((item) => item.programExists === false).length} orphan candidates</span></h3><p>A missing program can indicate an old app helper. Review it in Finder. Clean My Mac will not stop or remove services.</p>{insights.launchAgents.length ? insights.launchAgents.map((item) => <div className="insight-row" key={item.path}><strong>{item.label}{item.programExists === false && <em>Missing program candidate</em>}</strong><small>{item.path}{item.program ? ` · ${item.program}` : ""}</small></div>) : <p>No launch services found.</p>}</article>
        <article className="insight-card"><h3>Deleted files still open <span>{insights.deletedOpenFiles.length}</span></h3><p>Disk space returns when the process closes the deleted file. No process is stopped by this app.</p>{insights.deletedOpenFiles.length ? insights.deletedOpenFiles.map((item) => <div className="insight-row" key={`${item.pid}:${item.path}`}><strong>{item.process} <small>PID {item.pid}</small><b>{formatBytes(item.bytes)}</b></strong><small>{item.path}</small></div>) : <p>No deleted open files found.</p>}</article>
        <article className="insight-card docker-insight"><h3>Docker storage <span>{insights.docker?.available ? "Read only" : "Unavailable"}</span></h3><p>Docker CLI storage totals. Volumes can contain valuable databases and project data, so this is a read-only breakdown.</p><button className="button secondary" onClick={() => openSettings("docker")}>Open Docker Desktop</button>{insights.docker?.error && <p role="status">{insights.docker.error}</p>}{insights.docker?.available && (insights.docker.rows.length ? <div className="docker-table" role="table" aria-label="Docker storage usage"><div className="docker-table-row docker-table-header" role="row"><span>Type</span><span>Items</span><span>Size</span><span>Reclaimable</span></div>{insights.docker.rows.map((row) => <div className="docker-table-row" role="row" key={row.kind}><strong>{row.kind}</strong><span>{row.active}/{row.total} active</span><span>{row.size}</span><span>{row.reclaimable}</span></div>)}</div> : <p>Docker reported no storage categories.</p>)}{!insights.docker?.available && !insights.docker?.error && <p>Docker storage details are unavailable on this Mac.</p>}</article>
      </div>
      {insights.warnings.length > 0 && <ul className="insight-warnings">{insights.warnings.map((warning, index) => <li key={index}>{warning}</li>)}</ul>}
    </>}
  </section>;
}
function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
function pathsOverlap(left: string, right: string): boolean {
  const normalizedLeft = left.replace(/\/+$/, "");
  const normalizedRight = right.replace(/\/+$/, "");
  return (
    normalizedLeft === normalizedRight ||
    normalizedLeft.startsWith(`${normalizedRight}/`) ||
    normalizedRight.startsWith(`${normalizedLeft}/`)
  );
}

export default function App() {
  const [view, setView] = useState<View>("overview");
  const [report, setReport] = useState<ScanReport | null>(null);
  const [scanning, setScanning] = useState(false);
  const [cleaning, setCleaning] = useState(false);
  const [addingFolder, setAddingFolder] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [riskAcknowledged, setRiskAcknowledged] = useState(false);
  const [expanded, setExpanded] = useState<Set<Category>>(new Set());
  const [limits, setLimits] = useState<Partial<Record<Category, number>>>({});
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  const [deepScan, setDeepScan] = useState(true);
  const [source, setSource] = useState("all");
  const [sort, setSort] = useState<"largest" | "oldest" | "source">("largest");
  const [insights, setInsights] = useState<SystemInsights | null>(null);
  const [insightsBusy, setInsightsBusy] = useState(false);
  const [insightsError, setInsightsError] = useState<string | null>(null);
  const [lastCleanup, setLastCleanup] = useState<string | null>(null);
  const [lastCleanupWasGit, setLastCleanupWasGit] = useState(false);
  const [lastCleanupHadFailures, setLastCleanupHadFailures] = useState(false);
  const [modal, setModal] = useState<"cleanup" | "help" | "receipt" | null>(
    null,
  );
  const [movedItems, setMovedItems] = useState<ScanItem[]>([]);
  const [notice, setNotice] = useState<{ text: string; error: boolean } | null>(
    null,
  );
  const scanRunning = useRef(false);
  const findingsRef = useRef<HTMLElement>(null);
  const items = report?.items ?? [];
  const eligible = eligibleItems(items);
  const chosen = selectedItems(items, selected);
  const chosenBytes = totalBytes(chosen);
  const needsRiskAcknowledgement = chosen.some(
    (item) => item.requiresAck ?? item.risk !== "safe",
  );
  const hasGit = chosen.some((item) => item.cleanupKind === "git");
  const gitCount = chosen.filter((item) => item.cleanupKind === "git").length;
  const trashCount = chosen.length - gitCount;
  const receiptGitCount = movedItems.filter((item) => item.cleanupKind === "git").length;
  const receiptTrashCount = movedItems.length - receiptGitCount;
  const recommended = eligible.filter((item) => item.risk === "safe");
  const reclaimable = totalBytes(eligible);
  const usedBytes = report
    ? Math.max(0, report.volume.totalBytes - (report.volume.freeBytes ?? report.volume.availableBytes))
    : 0;
  const usedPercent =
    report && report.volume.totalBytes > 0
      ? Math.min(100, (usedBytes / report.volume.totalBytes) * 100)
      : 0;
  const knownPercent =
    report && report.volume.totalBytes > 0
      ? Math.min(
          usedPercent,
          (totalBytes(items) / report.volume.totalBytes) * 100,
        )
      : 0;

  async function scan(deep = deepScan) {
    if (scanRunning.current) return;
    scanRunning.current = true;
    setScanning(true);
    setNotice(null);
    try {
      const next = await scanSystem(deep);
      setReport(next);
      setSelected(new Set());
    } catch (error) {
      setNotice({ text: errorMessage(error), error: true });
    } finally {
      setScanning(false);
      scanRunning.current = false;
    }
  }
  async function loadInsights() {
    setInsightsBusy(true);
    setInsightsError(null);
    try { setInsights(await systemInsights()); }
    catch (error) { setInsightsError(errorMessage(error)); }
    finally { setInsightsBusy(false); }
  }
  async function settings(section: "storage" | "timeMachine" | "loginItems" | "diskUtility" | "trash" | "docker") {
    try { await openSystemSettings(section); }
    catch (error) { setNotice({ text: errorMessage(error), error: true }); }
  }
  async function addFolder() {
    if (!report || scanning || cleaning || addingFolder) return;
    setAddingFolder(true);
    setNotice(null);
    try {
      const picked = await pickCleanupFolder(report.id);
      if (!picked) return;

      const existing = report.items.find((item) => item.path === picked.path);
      const item = existing ? { ...picked, id: existing.id } : picked;
      const remaining = new Set(
        [...selected].filter((id) => {
          if (id === item.id) return true;
          const selectedItem = report.items.find((candidate) => candidate.id === id);
          return !selectedItem || !pathsOverlap(selectedItem.path, picked.path);
        }),
      );
      if (!remaining.has(item.id) && remaining.size >= MAX_SELECTION) {
        setNotice({
          text: "Selection is limited to 5,000 items. Remove some items before adding this folder.",
          error: false,
        });
        return;
      }

      setReport((previous) => {
        if (!previous) return previous;
        const existingIndex = previous.items.findIndex(
          (candidate) => candidate.path === picked.path,
        );
        if (existingIndex < 0) return { ...previous, items: [...previous.items, picked] };
        const items = [...previous.items];
        items[existingIndex] = item;
        return { ...previous, items };
      });
      remaining.add(item.id);
      setSelected(remaining);
      setRiskAcknowledged(false);
      setView("developer");
      setExpanded(new Set<Category>(["developer"]));
      setFilter("all");
      setQuery("");
      setLimits((previous) => ({
        ...previous,
        developer: Math.max(
          previous.developer ?? 30,
          report.items.filter((candidate) => candidate.category === "developer")
            .length + 1,
        ),
      }));
    } catch (error) {
      setNotice({ text: errorMessage(error), error: true });
    } finally {
      setAddingFolder(false);
    }
  }
  useEffect(() => {
    void scan();
  }, []);
  useEffect(() => {
    if (modal !== "cleanup") setRiskAcknowledged(false);
  }, [modal]);

  function navigate(next: View) {
    setView(next);
    setFilter("all");
    setSource("all");
    setQuery("");
    if (next !== "overview" && next !== "system") setExpanded(new Set([next]));
  }
  function toggleItem(item: ScanItem) {
    if (!item.cleanable || item.risk === "protected") return;
    if (!selected.has(item.id) && selected.size >= MAX_SELECTION) {
      setNotice({
        text: "Choose up to 5,000 items at a time. Clear this selection, then scan again for more.",
        error: false,
      });
      return;
    }
    setSelected((previous) => {
      const next = new Set(previous);
      if (next.has(item.id)) next.delete(item.id);
      else next.add(item.id);
      return next;
    });
    setRiskAcknowledged(false);
  }
  function toggleGroup(group: ScanItem[]) {
    const selectable = eligibleItems(group);
    const all =
      selectable.length > 0 &&
      selectable.every((item) => selected.has(item.id));
    if (
      !all &&
      new Set([...selected, ...selectable.map((item) => item.id)]).size >
        MAX_SELECTION
    ) {
      setNotice({
        text: "Selection is limited to 5,000 items. Clear this batch before selecting more.",
        error: false,
      });
    }
    setSelected((previous) => {
      const next = new Set(previous);
      for (const item of selectable) {
        if (all) next.delete(item.id);
        else if (next.size < MAX_SELECTION) next.add(item.id);
      }
      return next;
    });
    setRiskAcknowledged(false);
  }
  function selectRecommended() {
    setSelected(
      new Set(recommended.slice(0, MAX_SELECTION).map((item) => item.id)),
    );
    setRiskAcknowledged(false);
    if (recommended.length > MAX_SELECTION) {
      setNotice({
        text: "Selected the first 5,000 recommended items. You can clear the rest in another pass.",
        error: false,
      });
    }
  }
  function showEligibleFindings() {
    setView("overview");
    setFilter("eligible");
    setSource("all");
    setQuery("");
    setExpanded(
      new Set(
        categories
          .filter((category) => eligible.some((item) => item.category === category.id))
          .map((category) => category.id),
      ),
    );
    requestAnimationFrame(() =>
      findingsRef.current?.scrollIntoView?.({ behavior: "smooth", block: "start" }),
    );
  }
  function selectAllEligible() {
    setSelected(new Set(eligible.slice(0, MAX_SELECTION).map((item) => item.id)));
    setRiskAcknowledged(false);
    if (eligible.length > MAX_SELECTION) {
      setNotice({
        text: `Selected the first ${MAX_SELECTION.toLocaleString()} eligible items. Clear this batch before selecting the rest.`,
        error: false,
      });
    }
  }
  function toggleExpanded(category: Category) {
    setExpanded((previous) => {
      const next = new Set(previous);
      if (next.has(category)) next.delete(category);
      else next.add(category);
      return next;
    });
  }
  async function reveal(item: ScanItem) {
    if (!report) return;
    try {
      await revealItem(report.id, item.id);
    } catch (error) {
      setNotice({ text: errorMessage(error), error: true });
    }
  }
  async function cleanup() {
    if (!report || cleaning || !chosen.length || previewMode) return;
    setCleaning(true);
    setNotice(null);
    try {
      const result = await trashItems(
        report.id,
        chosen.map((item) => item.id),
        needsRiskAcknowledgement && riskAcknowledged,
      );
      const removed = new Set(result.trashedIds);
      const completedItems = chosen.filter((item) => removed.has(item.id));
      const completedGitCount = completedItems.filter((item) => item.cleanupKind === "git").length;
      const completedTrashItems = completedItems.filter((item) => item.cleanupKind !== "git");
      const completedTrashCount = completedTrashItems.length;
      setMovedItems(completedItems);
      setReport((previous) =>
        previous
          ? {
              ...previous,
              items: previous.items.filter((item) => !removed.has(item.id)),
              volume: result.volumeAfter ?? (result.freeBytesAfter == null ? previous.volume : {
                ...previous.volume,
                freeBytes: result.freeBytesAfter,
                availableBytes: result.freeBytesAfter,
              }),
            }
          : previous,
      );
      setSelected(new Set());
      setRiskAcknowledged(false);
      setModal(null);
      const movedBytes = result.movedBytes ?? totalBytes(completedTrashItems);
      let summary = completedItems.length === 0
        ? "No selected items were cleaned."
        : `${completedItems.length} item${completedItems.length === 1 ? "" : "s"} ${completedGitCount && completedTrashCount ? "cleaned" : completedGitCount ? "cleaned through Git" : "moved to Trash"}.`;
      if (completedGitCount && completedTrashCount) summary = `${completedGitCount} worktree${completedGitCount === 1 ? "" : "s"} cleaned through Git and ${completedTrashCount} item${completedTrashCount === 1 ? "" : "s"} moved to Trash.`;
      if (completedGitCount) summary += " Git worktree branches are preserved, but their files cannot be restored from Trash.";
      if (completedTrashCount) summary += ` Moved data: ${formatBytes(movedBytes)}. Trash items still occupy disk space until Trash is emptied.`;
      if (result.freeBytesBefore != null && result.freeBytesAfter != null) summary += ` Free space: ${formatBytes(result.freeBytesBefore)} before, ${formatBytes(result.freeBytesAfter)} after.`;
      if (result.failures.length) summary += ` ${result.failures.length} item(s) were kept: ${result.failures.map((failure) => failure.message).join(" ")}`;
      setLastCleanup(summary);
      setLastCleanupWasGit(completedGitCount > 0 && completedTrashCount === 0);
      setLastCleanupHadFailures(result.failures.length > 0);
      setNotice({
        text: summary,
        error: result.failures.length > 0,
      });
    } catch (error) {
      setNotice({ text: errorMessage(error), error: true });
      setModal(null);
    } finally {
      setCleaning(false);
    }
  }
  const filteredItems = useMemo(
    () =>
      items.filter((item) => {
        const matchesFilter =
          filter === "all" ||
          (filter === "eligible"
            ? item.cleanable && item.risk !== "protected"
            : filter === "recommended"
            ? item.risk === "safe" && item.cleanable
            : item.risk !== "safe" || !item.cleanable);
        return (
          matchesFilter &&
          (source === "all" || item.source === source) &&
          `${item.name} ${item.source} ${item.path}`
            .toLowerCase()
            .includes(query.toLowerCase())
        );
      }),
    [items, filter, query, source],
  );
  const displayedItems = useMemo(() => [...filteredItems].sort((a, b) => sort === "oldest" ? a.modifiedAt - b.modifiedAt : sort === "source" ? a.source.localeCompare(b.source) : b.bytes - a.bytes), [filteredItems, sort]);
  useEffect(() => { if (view === "system") void loadInsights(); }, [view]);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="titlebar-drag" data-tauri-drag-region />
        <div className="brand">
          <span className="brand-mark">
            <Sparkles size={24} strokeWidth={1.8} />
          </span>
          <span>
            Clean My Mac
            <span className="brand-subtitle">
              A little more breathing room.
            </span>
          </span>
        </div>
        <div className="nav-label">YOUR MAC</div>
        <nav aria-label="Main navigation">
          <button
            className={`nav-item ${view === "overview" ? "active" : ""}`}
            onClick={() => navigate("overview")}
          >
            <LayoutDashboard size={18} />
            <span>Overview</span>
          </button>
          <div className="nav-divider" />
          {categories.map((category) => {
            const Icon = icons[category.id];
            const count = items.filter(
              (item) => item.category === category.id,
            ).length;
            return (
              <button
                key={category.id}
                className={`nav-item ${view === category.id ? "active" : ""}`}
                onClick={() => navigate(category.id)}
              >
                <Icon size={18} />
                <span>{category.name}</span>
                {count > 0 && (
                  <span className="nav-count">{count.toLocaleString()}</span>
                )}
              </button>
            );
          })}
          <button className={`nav-item ${view === "system" ? "active" : ""}`} onClick={() => navigate("system")}><Activity size={18} /><span>System insights</span></button>
        </nav>
        <div className="sidebar-bottom">
          <div className="local-card">
            <span className="local-icon">
              <ShieldCheck size={19} />
            </span>
            <div>
              On your Mac. Only.<p>No uploads. No account.</p>
            </div>
          </div>
          <button className="help-button" onClick={() => setModal("help")}>
            <CircleHelp size={17} />
            How cleanup works
            <ChevronRight size={14} />
          </button>
          <div className="version">
            Clean My Mac <span>v0.2.1</span>
          </div>
        </div>
      </aside>

      <div className="main-shell">
        <header className="topbar" data-tauri-drag-region>
          <div className="breadcrumb">
            <HardDrive size={15} />
            <span>My Mac</span>
            <ChevronRight size={12} />
            <strong>{viewTitles[view]}</strong>
          </div>
          <div className={`local-status ${previewMode ? "preview" : ""}`}>
            <span />
            {previewMode ? "Preview · sample data" : "Local & private"}
          </div>
        </header>
        <main>
          <section className="page-heading">
            <div>
              <div className="eyebrow">
                {view === "overview"
                  ? "LESS CLUTTER. MORE POSSIBILITY."
                  : view === "system" ? "READ ONLY. LOCAL DIAGNOSTICS." : "A CLOSER LOOK"}
              </div>
              <h1>
                {view === "overview"
                  ? "Room for what’s next."
                  : viewTitles[view]}
              </h1>
              <p>
                {view === "overview"
                  ? "Clear out the leftovers. Keep what matters."
                  : view === "system" ? "Find what storage scans can miss, with context before you act." : categories.find((category) => category.id === view)
                      ?.description + ". You decide what goes."}
              </p>
            </div>
            <div className="page-actions">
              {view !== "system" && <label className="deep-toggle"><input type="checkbox" checked={deepScan} onChange={(event) => setDeepScan(event.currentTarget.checked)} /> Deep scan</label>}
              <button
                className="button secondary scan-button"
                disabled={scanning || cleaning || addingFolder}
                onClick={() => void scan()}
              >
                <RefreshCw size={15} className={scanning ? "spin" : ""} />
                {scanning ? (deepScan ? "Deep scan in progress…" : "Scanning your Mac…") : "Scan again"}
              </button>
              <button
                className="button secondary scan-button"
                disabled={!report || scanning || cleaning || addingFolder}
                onClick={() => void addFolder()}
              >
                <FolderPlus size={15} />
                {addingFolder ? "Choosing folder…" : "Add folder"}
              </button>
            </div>
          </section>

          {notice && (
            <div
              className={`notice ${notice.error ? "error" : "success"}`}
              role={notice.error ? "alert" : "status"}
            >
              <Info size={17} />
              <span>
                {notice.text}
                {lastCleanup && notice.text === lastCleanup && !lastCleanupWasGit && <button className="text-button" onClick={() => void settings("trash")}>Open Trash in Finder <ArrowRight size={13}/></button>}
                {movedItems.length > 0 && (
                  <button
                    className="text-button"
                    onClick={() => setModal("receipt")}
                  >
                    View moved files and original locations
                    <ArrowRight size={13} />
                  </button>
                )}
              </span>
              <button
                className="icon-button"
                aria-label="Dismiss notification"
                onClick={() => setNotice(null)}
              >
                <X size={16} />
              </button>
            </div>
          )}
          {lastCleanup && !notice && <div role={lastCleanupHadFailures ? "alert" : "status"} className={`notice ${lastCleanupHadFailures ? "error" : "success"} persistent-cleanup`}><Info size={17}/><span>Last cleanup: {lastCleanup}{!lastCleanupWasGit && <button className="text-button" onClick={() => void settings("trash")}>Open Trash in Finder <ArrowRight size={13}/></button>}{movedItems.length > 0 && <button className="text-button" onClick={() => setModal("receipt")}>View moved files and original locations <ArrowRight size={13}/></button>}</span></div>}

            {view === "overview" && (
            <>
              <section className="storage-card" aria-label="Disk storage">
                <div className="storage-heading">
                  <div className="volume-name">
                    <span className="drive-icon">
                      <HardDrive size={23} strokeWidth={1.5} />
                    </span>
                    <div>
                      <h2>{report?.volume.name ?? "Macintosh HD"}</h2>
                      <p>Internal storage</p>
                    </div>
                  </div>
                  <div className="storage-total">
                    {report ? (
                      <>
                        <strong>{formatBytes(usedBytes)}</strong>
                        <span>
                          {" "}
                          of {formatBytes(report.volume.totalBytes)} used
                        </span>
                      </>
                    ) : (
                      <span>Reading your storage…</span>
                    )}
                  </div>
                </div>
                <div
                  className={`storage-bar ${scanning && !report ? "loading-bar" : ""}`}
                  aria-label={
                    report
                      ? `${Math.round(usedPercent)} percent of disk used`
                      : "Reading disk"
                  }
                >
                  <span
                    className="storage-used"
                    style={{
                      width: `${Math.max(0, usedPercent - knownPercent)}%`,
                    }}
                  />
                  <span
                    className="storage-scanned"
                    style={{ width: `${knownPercent}%` }}
                  />
                </div>
                <div className="storage-legend">
                  <span>
                    <i className="dot other" />
                    Other used space
                  </span>
                  <span>
                    <i className="dot purple" />
                    Scanned files
                    {report && ` · ${formatBytes(totalBytes(items))}`}
                  </span>
                  <span className="available-legend">
                    <i className="dot available" />
                    {report
                      ? `${formatBytes(report.volume.freeBytes ?? report.volume.availableBytes)} free`
                      : "Calculating…"}
                  </span>
                </div>
                {report?.volume.purgeableBytes != null && <p className="storage-context">{formatBytes(report.volume.purgeableBytes)} potentially reclaimable. macOS may keep this space until needed.</p>}
                {report?.volume.availableForImportantUsageBytes != null && <p className="storage-context">macOS reports {formatBytes(report.volume.availableForImportantUsageBytes)} available for important use. This includes reclaimable space and differs from free space.</p>}
              </section>
              <section className="stats-grid" aria-label="Scan summary">
                <button
                  className="stat-card highlight stat-action"
                  onClick={showEligibleFindings}
                  disabled={!eligible.length}
                  aria-label={`Potential cleanup, ${formatBytes(reclaimable)} across ${eligible.length.toLocaleString()} eligible items. Show eligible findings`}
                >
                  <div className="stat-label">
                    <Sparkles size={16} />
                    Potential cleanup
                  </div>
                  <div className="stat-value">
                    {report ? formatBytes(reclaimable) : "…"}
                    <span className="stat-sparkle">
                      <Sparkles size={35} strokeWidth={1.2} />
                    </span>
                  </div>
                  <p>
                    Across {eligible.length.toLocaleString()} eligible items
                  </p>
                </button>
                <button
                  className="stat-card stat-link"
                  onClick={() => navigate("agents")}
                >
                  <div className="stat-label">
                    <Bot size={16} />
                    Agent sessions
                  </div>
                  <div className="stat-value">
                    {report
                      ? formatBytes(
                          totalBytes(
                            items.filter((item) => item.category === "agents"),
                          ),
                        )
                      : "…"}
                    <ArrowRight size={18} />
                  </div>
                  <p>Old conversations, a fresh start</p>
                </button>
                <div className="stat-card">
                  <div className="stat-label">
                    <ShieldCheck size={16} />
                    You’re in control
                  </div>
                  <div className="stat-value text-value">
                    Review. Then clear.
                  </div>
                  <p>Files go to Trash, so you can restore them</p>
                </div>
              </section>
            </>
          )}

          {view === "system" && <SystemInsightsPanel insights={insights} busy={insightsBusy} error={insightsError} retry={() => void loadInsights()} openSettings={(section) => void settings(section)} />}
          <section ref={findingsRef} className={`findings ${view === "system" ? "system-hidden" : ""}`} aria-labelledby="findings-title">
            <div className="section-heading">
              <div>
                <h2 id="findings-title">
                  {view === "overview"
                    ? "A little tidying goes a long way"
                    : `Inside ${viewTitles[view].toLowerCase()}`}
                </h2>
                <p>
                  {scanning
                    ? "Looking through known clutter folders. Your files stay untouched."
                    : report
                      ? `Last scanned ${new Date(report.scannedAt).toLocaleTimeString("en", { hour: "2-digit", minute: "2-digit" })} · Nothing is removed without your review`
                      : "Scan your Mac to find files you can clear"}
                </p>
              </div>
            </div>
            {scanning && <div className="scan-active-note" role="status">Selection is paused while the scan refreshes these findings. Your current selection will be cleared when it finishes.</div>}
            {report?.coverage && <div className="coverage-note" role="status">{report.coverage.mode === "deep" ? "Deep scan" : "Quick scan"} · {report.coverage.detectors} detectors · {report.coverage.visitedEntries.toLocaleString()} entries checked · {(report.coverage.elapsedMs / 1000).toFixed(1)}s{report.warnings.length ? ` · Partial scan: ${report.warnings.length} notes` : " · Scan complete"}</div>}
            <div className="findings-toolbar">
              <div className="filters" aria-label="Filter results">
                {(
                  [
                    ["all", "All files"],
                    ["eligible", "Can clean"],
                    ["recommended", "Recommended"],
                    ["review", "Needs a look"],
                  ] as const
                ).map(([id, label]) => (
                  <button
                    key={id}
                    aria-pressed={filter === id}
                    className={filter === id ? "selected" : ""}
                    onClick={() => setFilter(id)}
                  >
                    {label}
                  </button>
                ))}
              </div>
              <label className="source-select">Source<select aria-label="Filter by source" value={source} onChange={(event) => setSource(event.target.value)}><option value="all">All sources</option>{[...new Set(items.map((item) => item.source))].sort().map((value) => <option key={value}>{value}</option>)}</select></label>
              <label className="source-select">Sort<select aria-label="Sort results" value={sort} onChange={(event) => setSort(event.target.value as typeof sort)}><option value="largest">Largest</option><option value="oldest">Oldest</option><option value="source">Source</option></select></label>
              <label className="search">
                <Search size={15} />
                <input
                  aria-label="Search files"
                  placeholder="Find something…"
                  value={query}
                  onChange={(event) => setQuery(event.target.value)}
                />
              </label>
            </div>
            <div
              className={`findings-list ${scanning ? "is-scanning" : ""}`}
              aria-busy={scanning}
            >
              {scanning && !report ? (
                <div className="empty-state">
                  <LoaderCircle className="spin" size={30} />
                  <h3>Finding a little breathing room</h3>
                  <p>Checking agent sessions, caches, and developer files.</p>
                </div>
              ) : !report ? (
                <div className="empty-state">
                  <FileSearch size={30} />
                  <h3>Your files are ready for a fresh look</h3>
                  <p>Run a scan to find old sessions and temporary files.</p>
                  <button
                    className="button primary"
                    onClick={() => void scan()}
                  >
                    Scan my Mac
                  </button>
                </div>
              ) : (
                categories
                  .filter(
                    (category) => view === "overview" || view === category.id,
                  )
                  .map((category) => {
                    const group = displayedItems.filter(
                      (item) => item.category === category.id,
                    );
                    const Icon = icons[category.id];
                    if ((filter !== "all" || query) && !group.length)
                      return null;
                    const selectable = eligibleItems(group);
                    const selectedCount = selectable.filter((item) =>
                      selected.has(item.id),
                    ).length;
                    const isOpen = expanded.has(category.id);
                    return (
                      <div className="category" key={category.id}>
                        <div className="category-row">
                          <input
                            type="checkbox"
                            className="checkbox"
                            aria-label={`Select ${category.name}`}
                            checked={
                              selectable.length > 0 &&
                              selectedCount === selectable.length
                            }
                            ref={(node) => {
                              if (node)
                                node.indeterminate =
                                  selectedCount > 0 &&
                                  selectedCount < selectable.length;
                            }}
                            onChange={() => toggleGroup(group)}
                            disabled={
                              !selectable.length || scanning || cleaning
                            }
                          />
                          <button
                            className="category-toggle"
                            onClick={() => toggleExpanded(category.id)}
                            aria-expanded={isOpen}
                          >
                            <span className={`category-icon ${category.color}`}>
                              <Icon size={22} strokeWidth={1.7} />
                            </span>
                            <span className="category-text">
                              <strong>
                                {category.name}
                                {category.id === "agents" && (
                                  <span className="badge">YOUR AGENTS</span>
                                )}
                              </strong>
                              <span>
                                {group.length
                                  ? `${group.length.toLocaleString()} item${group.length === 1 ? "" : "s"} · ${category.description}`
                                  : "No matching files found"}
                              </span>
                            </span>
                            <span className="category-size">
                              {formatBytes(totalBytes(group))}
                            </span>
                            {isOpen ? (
                              <ChevronDown size={17} />
                            ) : (
                              <ChevronRight size={17} />
                            )}
                          </button>
                        </div>
                        {isOpen && (
                          <div className="file-list">
                            {group
                              .slice(0, limits[category.id] ?? 30)
                              .map((item) => (
                                <div className="file-row" key={item.id}>
                                  <input
                                    type="checkbox"
                                    className="checkbox"
                                    aria-label={`Select ${item.name}`}
                                    title={item.reason ?? item.description}
                                    checked={selected.has(item.id)}
                                    disabled={
                                      !item.cleanable ||
                                      item.risk === "protected" ||
                                      scanning ||
                                      cleaning
                                    }
                                    onChange={() => toggleItem(item)}
                                  />
                                  <div className="file-info">
                                    <div className="file-name">
                                      {item.name}
                                      <span className={`risk-tag ${item.risk}`}>
                                        {item.category === "large" &&
                                        !item.cleanable ? (
                                          "Finder only"
                                        ) : item.risk === "protected" ||
                                          !item.cleanable ? (
                                          <>
                                            <LockKeyhole size={10} />
                                            Kept
                                          </>
                                        ) : item.risk === "safe" ? (
                                          "Recommended"
                                        ) : (
                                          "Review first"
                                        )}
                                      </span>
                                      {item.source === "Added by you" && (
                                        <span className="badge">Added by you</span>
                                      )}
                                    </div>
                                    <div
                                      className="file-path"
                                      title={item.path}
                                    >
                                      {item.path}
                                    </div>
                                    <p>{item.reason || item.description}{!item.cleanable && ` ${item.reason || "This item is read-only. Use Finder to review it."}`}{item.details ? ` ${item.details}` : ""}</p>
                                  </div>
                                  <div className="file-meta">
                                    <strong>{formatBytes(item.bytes)}</strong>
                                      {item.allocatedBytes != null && Math.abs(item.allocatedBytes - item.bytes) > item.bytes * 0.1 && <span>On disk {formatBytes(item.allocatedBytes)}</span>}
                                    <span>{ageLabel(item.modifiedAt)}</span>
                                  </div>
                                  <button
                                    className="icon-button reveal-button"
                                    aria-label={`Show ${item.name} in Finder`}
                                    title="Show in Finder"
                                    onClick={() => void reveal(item)}
                                  >
                                    <FolderOpen size={17} />
                                  </button>
                                </div>
                              ))}
                            {group.length > (limits[category.id] ?? 30) && (
                              <button
                                className="show-more"
                                onClick={() =>
                                  setLimits((previous) => ({
                                    ...previous,
                                    [category.id]:
                                      (previous[category.id] ?? 30) + 30,
                                  }))
                                }
                              >
                                Show more files (
                                {group.length - (limits[category.id] ?? 30)}{" "}
                                remaining)
                                <ChevronDown size={14} />
                              </button>
                            )}
                            {!group.length && (
                              <p className="category-empty">
                                Nothing to tidy up here.
                              </p>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })
              )}
              {report && view !== "system" &&
                !scanning &&
                !filteredItems.some(
                  (item) => view === "overview" || item.category === view,
                ) &&
                (filter !== "all" || query) && (
                  <div className="empty-state compact">
                    <Search size={24} />
                    <h3>No matching files</h3>
                    <p>Try another search or filter.</p>
                  </div>
                )}
            </div>
            {report && report.warnings.length > 0 && (
              <details className="scan-warnings">
                <summary>
                  <Info size={14} />
                  Scan notes ({report.warnings.length})<ChevronDown size={14} />
                </summary>
                <ul>
                  {report.warnings.map((warning, index) => (
                    <li key={index}>{warning}</li>
                  ))}
                </ul>
              </details>
            )}
            <div className="scan-footnote">
              <ShieldCheck size={14} />
              <span>
                Your credentials and app settings stay out of cleanup.
              </span>
              <span className="scope-note">Known clutter folders only</span>
            </div>
          </section>
        </main>
        <footer className="action-bar">
          <div className="selection-summary">
            <span
              className={`selection-icon ${chosen.length ? "has-selection" : ""}`}
            >
              <CheckCheck size={20} />
            </span>
            <div>
              <strong>
                {chosen.length
                  ? `${formatBytes(chosenBytes)} selected`
                  : "A clean Mac. On your terms."}
              </strong>
              <p>
                {chosen.length
                  ? `${chosen.length.toLocaleString()} item${chosen.length === 1 ? "" : "s"} ready for your review`
                  : "Choose what you’d like to clear above."}
              </p>
            </div>
          </div>
          <div className="action-buttons">
            {selected.size > 0 && (
              <button
                className="text-button"
                onClick={() => {
                  setSelected(new Set());
                  setRiskAcknowledged(false);
                }}
                disabled={scanning || cleaning}
              >
                Deselect all
              </button>
            )}
            <button
              className="text-button"
              disabled={scanning || cleaning || !eligible.length}
              onClick={selectAllEligible}
            >
              <CheckCheck size={14} />
              Select all eligible
            </button>
            {recommended.length > 0 && (
              <button
                className="text-button"
                disabled={scanning || cleaning}
                onClick={selectRecommended}
              >
                <Check size={14} />
                Select recommended
              </button>
            )}
            <button
              className="button primary"
              disabled={!chosen.length || scanning || cleaning}
              onClick={() => {
                setRiskAcknowledged(false);
                setModal("cleanup");
              }}
            >
              Review cleanup
              <ArrowRight size={16} />
            </button>
          </div>
        </footer>
      </div>

      {modal === "help" && (
        <Modal
          title="A lighter Mac. A clear process."
          close={() => setModal(null)}
        >
          <div className="help-intro">
            <span className="help-hero">
              <ShieldCheck size={32} />
            </span>
            <p>
              Everything happens on your Mac. There is no account, cloud
              processing, or telemetry.
            </p>
          </div>
          <ol className="help-steps">
            <li>
              <strong>Scan known clutter folders</strong>
              <p>
                We automatically check known Codex and Claude Code history,
                niche app caches and logs, developer toolchains, build outputs,
                model download caches, Xcode files, package caches, project
                artifacts, and large Downloads. A deep scan checks more known
                locations and bounded project folders. You can also add a folder manually. Its contents
                will move together if you confirm cleanup.
              </p>
            </li>
            <li><strong>Understand system findings</strong><p>System insights can list local backup snapshots, background services with missing programs, processes using memory, and deleted files still held open. These are context only. They are not removed or stopped.</p></li>
            <li>
              <strong>Choose what can go</strong>
              <p>
                Recommendations are conservative. You can also select other
                eligible files after reviewing their paths and risk notes.
              </p>
            </li>
            <li>
              <strong>Review and move to Trash</strong>
              <p>
                Check the paths and confirm your selection. Files are rechecked
                before they move. To restore, drag them from Trash to their
                original folders. Finder’s Put Back option may be unavailable.
              </p>
            </li>
          </ol>
          <div className="help-note">
            <Info size={17} />
            <p>
              Files moved to Trash still occupy disk space until you empty Trash.
              Local snapshots may retain storage and macOS manages them when space is needed. Rebuilt caches and the first build after cleanup can take longer.
              macOS may block access to some folders; scan notes explain what
              was skipped.
            </p>
          </div>
          {movedItems.length > 0 && (
            <button
              className="button secondary full-width receipt-link"
              onClick={() => setModal("receipt")}
            >
              View the last cleanup
              <ArrowRight size={15} />
            </button>
          )}
          <button
            className="button primary full-width"
            onClick={() => setModal(null)}
          >
            Got it
            <Check size={16} />
          </button>
        </Modal>
      )}
      {modal === "cleanup" && (
        <Modal
          title="Review your cleanup"
          close={() => setModal(null)}
          busy={cleaning}
        >
          <div className="cleanup-overview">
            <span>
              <Trash2 size={25} />
            </span>
            <div>
              <strong>{formatBytes(chosenBytes)}</strong>
              <p>
                {hasGit && trashCount ? `${gitCount} worktree${gitCount === 1 ? "" : "s"} will be cleaned through Git and ${trashCount} item${trashCount === 1 ? "" : "s"} will move to Trash` : `${chosen.length.toLocaleString()} item${chosen.length === 1 ? "" : "s"} ${hasGit ? "will be cleaned through Git" : "will move to Trash"}`}
              </p>
            </div>
          </div>
          {hasGit && <div className="help-note caution"><Info size={17}/><p>Removing a Git worktree deletes its working files through Git and preserves its branch. This does not go to Trash and cannot be restored from Trash.</p></div>}
          {chosen.some((item) => item.category === "agents") && (
            <div className="help-note caution">
              <Info size={17} />
              <p>
                This includes agent conversations. You will lose access to their
                history and the ability to resume those sessions until the files
                are restored.
              </p>
            </div>
          )}
          {chosen.some((item) => item.source === "Added by you") && (
            <div className="help-note caution">
              <Info size={17} />
              <p>
                The added folder and all files inside it will move to Trash.
                Review its path and contents before continuing.
              </p>
            </div>
          )}
          <div className="review-list">
            {chosen.map((item) => (
              <div key={item.id}>
                <span>
                  <strong>{item.name}</strong>
                  <small title={item.path}>{item.path}</small>
                </span>
                <b>{formatBytes(item.bytes)}</b>
              </div>
            ))}
          </div>
          <p className="modal-caption">
            To restore, drag files from Trash to their original folders.
            Finder’s Put Back option may be unavailable. Space is freed when you
            empty Trash. Files changed since the scan will be skipped.
          </p>
          {needsRiskAcknowledgement && (
            <label className="risk-acknowledgement">
              <input
                type="checkbox"
                className="checkbox"
                checked={riskAcknowledged}
                onChange={(event) =>
                  setRiskAcknowledged(event.currentTarget.checked)
                }
              />
              <span>
                {hasGit ? "I understand Git worktree cleanup permanently removes the selected working files, while preserving the branch." : "I understand these files may be in use, contain history I need, or include personal data."}
              </span>
            </label>
          )}
          {previewMode && (
            <div className="preview-notice">
              <Info size={16} />
              This is sample data. Open the desktop app to clean your Mac.
            </div>
          )}
          <div className="modal-actions">
            <button
              className="button secondary"
              disabled={cleaning}
              onClick={() => setModal(null)}
            >
              Keep files
            </button>
            <button
              className="button primary"
              disabled={
                cleaning ||
                previewMode ||
                (needsRiskAcknowledgement && !riskAcknowledged)
              }
              onClick={() => void cleanup()}
            >
              {cleaning ? (
                <LoaderCircle className="spin" size={16} />
              ) : (
                <Trash2 size={16} />
              )}
              {cleaning ? (hasGit ? "Cleaning…" : "Moving to Trash…") : (hasGit ? "Confirm cleanup" : "Move to Trash")}
            </button>
          </div>
        </Modal>
      )}
      {modal === "receipt" && (
        <Modal title="Your last cleanup" close={() => setModal(null)}>
          <p className="modal-caption">
            {receiptGitCount > 0 && `${receiptGitCount} worktree${receiptGitCount === 1 ? " was" : "s were"} removed through Git. Its branch${receiptGitCount === 1 ? " remains" : "es remain"}; those files cannot be restored from Trash. `}
            {receiptTrashCount > 0 && `${receiptTrashCount} item${receiptTrashCount === 1 ? " was" : "s were"} moved to Trash. To restore one, drag it from Trash to its original folder. `}
            This list is available until you close the app or complete another cleanup.
          </p>
          <div className="review-list receipt-list">
            {movedItems.map((item) => (
              <div key={item.id}>
                <span>
                  <strong>{item.name}</strong>
                  <small>Original location</small>
                  <input
                    aria-label={`Original location of ${item.name}`}
                    readOnly
                    value={item.path}
                    onFocus={(event) => event.currentTarget.select()}
                  />
                </span>
                <b>{formatBytes(item.bytes)}</b>
              </div>
            ))}
          </div>
          <button
            className="button primary full-width receipt-link"
            onClick={() => setModal(null)}
          >
            Done
            <Check size={16} />
          </button>
        </Modal>
      )}
    </div>
  );
}
