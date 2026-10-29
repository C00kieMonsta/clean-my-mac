import { invoke, isTauri } from "@tauri-apps/api/core";
import type { CleanupResult, ScanReport } from "@clean-my-mac/core";
import { demoReport } from "./demo";

export const previewMode = !isTauri();

export async function scanSystem(): Promise<ScanReport> {
  if (previewMode) return structuredClone(demoReport);
  return invoke<ScanReport>("scan_system");
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
