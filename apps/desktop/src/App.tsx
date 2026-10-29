import { useEffect, useMemo, useRef, useState } from "react";
import {
  ArrowDownToLine,
  ArrowRight,
  Bot,
  Check,
  CheckCheck,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Code2,
  Database,
  FileSearch,
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
} from "@clean-my-mac/core";
import { previewMode, revealItem, scanSystem, trashItems } from "./lib/bridge";
import { Modal } from "./components/Modal";

type View = "overview" | Category;
type Filter = "all" | "recommended" | "review";
const MAX_SELECTION = 200;
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
};

function ageLabel(timestamp: number): string {
  const days = Math.max(0, Math.floor((Date.now() - timestamp) / 86_400_000));
  return days === 0 ? "Today" : `${days}d ago`;
}
function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export default function App() {
  const [view, setView] = useState<View>("overview");
  const [report, setReport] = useState<ScanReport | null>(null);
  const [scanning, setScanning] = useState(false);
  const [cleaning, setCleaning] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [riskAcknowledged, setRiskAcknowledged] = useState(false);
  const [expanded, setExpanded] = useState<Set<Category>>(new Set());
  const [limits, setLimits] = useState<Partial<Record<Category, number>>>({});
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  const [modal, setModal] = useState<"cleanup" | "help" | "receipt" | null>(
    null,
  );
  const [movedItems, setMovedItems] = useState<ScanItem[]>([]);
  const [notice, setNotice] = useState<{ text: string; error: boolean } | null>(
    null,
  );
  const scanRunning = useRef(false);
  const items = report?.items ?? [];
  const eligible = eligibleItems(items);
  const chosen = selectedItems(items, selected);
  const chosenBytes = totalBytes(chosen);
  const needsRiskAcknowledgement = chosen.some(
    (item) => item.requiresAck ?? item.risk !== "safe",
  );
  const recommended = eligible.filter((item) => item.risk === "safe");
  const reclaimable = totalBytes(eligible);
  const usedBytes = report
    ? Math.max(0, report.volume.totalBytes - report.volume.availableBytes)
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

  async function scan() {
    if (scanRunning.current) return;
    scanRunning.current = true;
    setScanning(true);
    setNotice(null);
    try {
      const next = await scanSystem();
      setReport(next);
      setSelected(new Set());
    } catch (error) {
      setNotice({ text: errorMessage(error), error: true });
    } finally {
      setScanning(false);
      scanRunning.current = false;
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
    setQuery("");
    if (next !== "overview") setExpanded(new Set([next]));
  }
  function toggleItem(item: ScanItem) {
    if (!item.cleanable || item.risk === "protected") return;
    if (!selected.has(item.id) && selected.size >= MAX_SELECTION) {
      setNotice({
        text: "Choose up to 200 items at a time. Clear this selection, then scan again for more.",
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
        text: "Selection is limited to 200 items. Clear this batch before selecting more.",
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
        text: "Selected the first 200 recommended items. You can clear the rest in another pass.",
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
      setMovedItems(chosen.filter((item) => removed.has(item.id)));
      setReport((previous) =>
        previous
          ? {
              ...previous,
              items: previous.items.filter((item) => !removed.has(item.id)),
            }
          : previous,
      );
      setSelected(new Set());
      setRiskAcknowledged(false);
      setModal(null);
      setNotice({
        text: `${result.trashedIds.length} item${result.trashedIds.length === 1 ? "" : "s"} moved to Trash (${formatBytes(result.reclaimedBytes)}). Empty Trash in Finder to free disk space.${result.failures.length ? ` ${result.failures.length} item(s) were kept: ${result.failures.map((failure) => failure.message).join(" ")}` : ""}`,
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
          (filter === "recommended"
            ? item.risk === "safe" && item.cleanable
            : item.risk !== "safe" || !item.cleanable);
        return (
          matchesFilter &&
          `${item.name} ${item.source} ${item.path}`
            .toLowerCase()
            .includes(query.toLowerCase())
        );
      }),
    [items, filter, query],
  );

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
            Clean My Mac <span>v0.1.0</span>
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
                  : "A CLOSER LOOK"}
              </div>
              <h1>
                {view === "overview"
                  ? "Room for what’s next."
                  : viewTitles[view]}
              </h1>
              <p>
                {view === "overview"
                  ? "Clear out the leftovers. Keep what matters."
                  : categories.find((category) => category.id === view)
                      ?.description + ". You decide what goes."}
              </p>
            </div>
            <button
              className="button secondary scan-button"
              disabled={scanning || cleaning}
              onClick={() => void scan()}
            >
              <RefreshCw size={15} className={scanning ? "spin" : ""} />
              {scanning ? "Scanning your Mac…" : "Scan again"}
            </button>
          </section>

          {notice && (
            <div
              className={`notice ${notice.error ? "error" : "success"}`}
              role={notice.error ? "alert" : "status"}
            >
              <Info size={17} />
              <span>
                {notice.text}
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
                      ? `${formatBytes(report.volume.availableBytes)} available`
                      : "Calculating…"}
                  </span>
                </div>
              </section>
              <section className="stats-grid" aria-label="Scan summary">
                <div className="stat-card highlight">
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
                </div>
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

          <section className="findings" aria-labelledby="findings-title">
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
            <div className="findings-toolbar">
              <div className="filters" aria-label="Filter results">
                {(
                  [
                    ["all", "All files"],
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
                    const group = filteredItems.filter(
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
                                    </div>
                                    <div
                                      className="file-path"
                                      title={item.path}
                                    >
                                      {item.path}
                                    </div>
                                    <p>{item.reason || item.description}</p>
                                  </div>
                                  <div className="file-meta">
                                    <strong>{formatBytes(item.bytes)}</strong>
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
              {report &&
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
                Your credentials, settings, and recent sessions stay put.
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
            {selected.size > 0 ? (
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
            ) : (
              <button
                className="text-button"
                disabled={scanning || cleaning || !recommended.length}
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
                We check Codex and Claude Code transcripts, selected app caches
                and logs, Xcode build files, package caches, and large
                Downloads.
              </p>
            </li>
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
              Disk space becomes available after you empty Trash in Finder.
              Rebuilt caches and the first build after cleanup can take longer.
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
                {chosen.length.toLocaleString()} item
                {chosen.length === 1 ? "" : "s"} will move to Trash
              </p>
            </div>
          </div>
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
            empty Trash. Changed or active files will be skipped.
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
                I understand these files may be in use or contain history I
                need.
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
              {cleaning ? "Moving to Trash…" : "Move to Trash"}
            </button>
          </div>
        </Modal>
      )}
      {modal === "receipt" && (
        <Modal title="Your last cleanup" close={() => setModal(null)}>
          <p className="modal-caption">
            These files were moved to Trash. To restore one, drag it from Trash
            into its original folder below. This list is available until you
            close the app or complete another cleanup.
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
