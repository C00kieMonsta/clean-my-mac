import { invoke, isTauri } from "@tauri-apps/api/core";
import type { CleanupResult, ScanItem, ScanReport, SystemInsights } from "@clean-my-mac/core";
import { demoReport } from "./demo";
import { demoInsights } from "./demo";

export const previewMode = !isTauri();

export async function scanSystem(deep = false): Promise<ScanReport> {
  if (previewMode) return { ...structuredClone(demoReport), coverage: { mode: deep ? "deep" : "quick", detectors: deep ? 48 : 18, visitedEntries: deep ? 4200 : 280, elapsedMs: deep ? 6400 : 1200 } };
  return invoke<ScanReport>("scan_system", { deep });
}

export async function storageCapacity(): Promise<ScanReport["volume"]> {
  if (previewMode) return structuredClone(demoReport.volume);
  return invoke<ScanReport["volume"]>("get_storage_capacity");
}

export async function systemInsights(): Promise<SystemInsights> {
  if (previewMode) return structuredClone(demoInsights);
  return invoke<SystemInsights>("get_system_insights");
}

export async function openSystemSettings(section: "storage" | "timeMachine" | "loginItems" | "diskUtility" | "trash" | "docker"): Promise<void> {
  if (previewMode) throw new Error("System Settings links are available in the Mac app.");
  return invoke<void>("open_system_settings", { section });
}

export async function pickCleanupFolder(scanId: string): Promise<ScanItem | null> {
  if (previewMode)
    throw new Error(
      "Folder selection is available in the Mac app. This preview uses sample data.",
    );
  return invoke<ScanItem | null>("pick_cleanup_folder", { scanId });
}

export async function trashItems(
  scanId: string,
  itemIds: string[],
  acknowledgeRisk = false,
): Promise<CleanupResult> {
  if (previewMode)
    throw new Error(
      "Open the Mac app to move files to Trash. This preview uses sample data.",
    );
  return invoke<CleanupResult>("trash_items", {
    scanId,
    itemIds,
    acknowledgeRisk,
  });
}

export async function revealItem(
  scanId: string,
  itemId: string,
): Promise<void> {
  if (previewMode)
    throw new Error(
      "Finder is available in the Mac app. This preview uses sample data.",
    );
  return invoke<void>("reveal_item", { scanId, itemId });
}
