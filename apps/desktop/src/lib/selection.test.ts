import { describe, expect, it } from "vitest";
import {
  eligibleItems,
  formatBytes,
  selectedItems,
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
