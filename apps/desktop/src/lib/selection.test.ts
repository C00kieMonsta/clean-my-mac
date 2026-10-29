import { describe, expect, it } from "vitest";
import {
  eligibleItems,
  formatBytes,
  selectedItems,
  storageUsage,
  totalBytes,
  type ScanItem,
} from "@clean-my-mac/core";

const fixture = (id: string, overrides: Partial<ScanItem> = {}): ScanItem => ({
  id,
  category: "caches",
  name: id,
  path: `/test/${id}`,
  bytes: 1000,
  fileCount: 1,
  modifiedAt: 0,
  description: "",
  source: "",
  risk: "safe",
  cleanable: true,
  ...overrides,
});

describe("cleanup selection boundaries", () => {
  const items = [
    fixture("cache"),
    fixture("session", { risk: "review", category: "agents" }),
    fixture("active", { risk: "protected" }),
    fixture("download", { cleanable: false, category: "large" }),
  ];
  it("excludes protected and read-only files even with a stale selection", () => {
    expect(
      selectedItems(
        items,
        new Set(["cache", "session", "active", "download", "unknown"]),
      ).map((item) => item.id),
    ).toEqual(["cache", "session"]);
  });
  it("does not count an unknown ID or an empty selection", () => {
    expect(selectedItems(items, new Set(["unknown"]))).toEqual([]);
    expect(totalBytes(selectedItems(items, new Set()))).toBe(0);
  });
  it("allows sessions only as reviewable eligible items", () => {
    expect(eligibleItems(items).map((item) => item.id)).toEqual([
      "cache",
      "session",
    ]);
  });
});

describe("disk units", () => {
  it("matches the decimal units used by macOS storage", () => {
    expect(formatBytes(1_000_000_000)).toBe("1 GB");
    expect(formatBytes(1_245_000_000)).toBe("1.2 GB");
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(Number.NaN)).toBe("0 B");
  });
});

describe("storage usage accounting", () => {
  it("matches macOS available space when purgeable data is included", () => {
    expect(storageUsage({
      name: "Macintosh HD",
      totalBytes: 994_662_584_320,
      freeBytes: 34_584_285_184,
      purgeableBytes: 410_709_035_499,
      availableForImportantUsageBytes: 445_293_320_683,
      availableBytes: 445_293_320_683,
    })).toEqual({
      totalBytes: 994_662_584_320,
      freeBytes: 34_584_285_184,
      availableBytes: 445_293_320_683,
      usedBytes: 549_369_263_637,
      purgeableBytes: 410_709_035_499,
    });
  });

  it("supports legacy volume reports and clamps invalid or inconsistent values", () => {
    expect(storageUsage({ name: "Legacy", totalBytes: 100, availableBytes: 25 })).toEqual({
      totalBytes: 100, freeBytes: 25, availableBytes: 25, usedBytes: 75, purgeableBytes: 0,
    });
    expect(storageUsage({
      name: "Invalid", totalBytes: 100, availableBytes: Number.NaN,
      freeBytes: -5, availableForImportantUsageBytes: Number.POSITIVE_INFINITY,
    })).toEqual({
      totalBytes: 100, freeBytes: 0, availableBytes: 0, usedBytes: 100, purgeableBytes: 0,
    });
    expect(storageUsage({ name: "Oversized", totalBytes: -1, availableBytes: 4, freeBytes: 8 })).toEqual({
      totalBytes: 0, freeBytes: 0, availableBytes: 0, usedBytes: 0, purgeableBytes: 0,
    });
  });
});
