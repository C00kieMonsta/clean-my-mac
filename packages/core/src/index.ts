export type Category = "agents" | "caches" | "developer" | "large";
export type Risk = "safe" | "review" | "protected";

export interface ScanItem {
  id: string;
  category: Category;
  name: string;
  path: string;
  bytes: number;
  allocatedBytes?: number;
  fileCount: number;
  modifiedAt: number;
  description: string;
  source: string;
  risk: Risk;
  cleanable: boolean;
  requiresAck?: boolean;
  reason?: string | null;
  cleanupKind?: "trash" | "git";
  details?: string;
}

export interface ScanCoverage {
  mode: "quick" | "deep";
  detectors: number;
  visitedEntries: number;
  elapsedMs: number;
}

export interface SystemInsights {
  snapshots: { name: string; volume: string; purgeable: boolean | null }[];
  processes: { pid: number; name: string; memoryBytes: number; cpuPercent: number }[];
  launchAgents: { path: string; label: string; program: string | null; programExists: boolean | null; system: boolean }[];
  deletedOpenFiles: { pid: number; process: string; path: string; bytes: number }[];
  docker?: {
    available: boolean;
    error?: string;
    rows: { kind: string; total: number; active: number; size: string; reclaimable: string }[];
  };
  warnings: string[];
}

export interface ScanReport {
  id: string;
  scannedAt: number;
  volume: { name: string; totalBytes: number; availableBytes: number; freeBytes?: number; purgeableBytes?: number; availableForImportantUsageBytes?: number };
  items: ScanItem[];
  warnings: string[];
  coverage?: ScanCoverage;
}

export interface CleanupResult {
  volumeAfter?: ScanReport["volume"] | null;
  trashedIds: string[];
  reclaimedBytes: number;
  movedBytes?: number;
  freeBytesBefore?: number;
  freeBytesAfter?: number;
  failures: { id: string; message: string }[];
}

export const categories: {
  id: Category;
  name: string;
  description: string;
  color: string;
}[] = [
  {
    id: "agents",
    name: "Agent sessions",
    description: "Old conversations and agent history",
    color: "purple",
  },
  {
    id: "caches",
    name: "Caches & logs",
    description: "Temporary files that apps can rebuild",
    color: "blue",
  },
  {
    id: "developer",
    name: "Developer files",
    description: "Build artifacts and package caches",
    color: "amber",
  },
  {
    id: "large",
    name: "Large files",
    description: "Review large downloads before clearing",
    color: "green",
  },
];

export function formatBytes(bytes: number, digits = 1): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const exponent = Math.min(
    Math.floor(Math.log(bytes) / Math.log(1000)),
    units.length - 1,
  );
  return `${(bytes / 1000 ** exponent).toLocaleString("en", { maximumFractionDigits: exponent === 0 ? 0 : digits })} ${units[exponent]}`;
}

export function eligibleItems(items: ScanItem[]): ScanItem[] {
  return items.filter((item) => item.cleanable && item.risk !== "protected");
}

export function selectedItems(
  items: ScanItem[],
  ids: ReadonlySet<string>,
): ScanItem[] {
  return eligibleItems(items).filter((item) => ids.has(item.id));
}

export function totalBytes(items: ScanItem[]): number {
  return items.reduce((sum, item) => sum + item.bytes, 0);
}
