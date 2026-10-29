import {
  afterEach,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";
import {
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import type { CleanupResult, ScanItem, ScanReport } from "@clean-my-mac/core";

const bridge = vi.hoisted(() => ({
  scanSystem: vi.fn(),
  pickCleanupFolder: vi.fn(),
  trashItems: vi.fn(),
  revealItem: vi.fn(),
  systemInsights: vi.fn(),
  openSystemSettings: vi.fn(),
}));

vi.mock("./lib/bridge", () => ({
  previewMode: false,
  scanSystem: bridge.scanSystem,
  pickCleanupFolder: bridge.pickCleanupFolder,
  trashItems: bridge.trashItems,
  revealItem: bridge.revealItem,
  systemInsights: bridge.systemInsights,
  openSystemSettings: bridge.openSystemSettings,
}));

import App from "./App";

const report: ScanReport = {
  id: "scan-123",
  scannedAt: 1_800_000_000_000,
  volume: {
    name: "Macintosh HD",
    totalBytes: 1_000_000_000_000,
    availableBytes: 250_000_000_000,
  },
  items: [
    {
      id: "session-old",
      category: "agents",
      name: "Old agent conversation",
      path: "~/.claude/projects/old.jsonl",
      bytes: 3_000_000,
      fileCount: 1,
      modifiedAt: 1_700_000_000_000,
      description: "Old conversation history.",
      source: "Claude Code",
      risk: "review",
      cleanable: true,
    },
    {
      id: "session-recent",
      category: "agents",
      name: "Recent agent conversation",
      path: "~/.codex/sessions/recent.jsonl",
      bytes: 2_000_000,
      fileCount: 1,
      modifiedAt: 1_799_000_000_000,
      description: "A recent session.",
      source: "Codex",
      risk: "review",
      cleanable: true,
    },
    {
      id: "cache-old",
      category: "caches",
      name: "Browser cache",
      path: "~/Library/Caches/Browser",
      bytes: 5_000_000,
      fileCount: 12,
      modifiedAt: 1_700_000_000_000,
      description: "Temporary browser data.",
      source: "Browser",
      risk: "safe",
      cleanable: true,
    },
    {
      id: "download-large",
      category: "large",
      name: "Personal installer.dmg",
      path: "~/Downloads/installer.dmg",
      bytes: 8_000_000,
      fileCount: 1,
      modifiedAt: 1_700_000_000_000,
      description: "A large personal download.",
      source: "Downloads",
      risk: "review",
      cleanable: true,
      reason: "Review this download before clearing.",
    },
    {
      id: "protected-config",
      category: "developer",
      name: "Protected configuration",
      path: "~/Library/Application Support/app/config.json",
      bytes: 1_000_000,
      fileCount: 1,
      modifiedAt: 1_700_000_000_000,
      description: "Configuration used by an app.",
      source: "App",
      risk: "protected",
      cleanable: true,
    },
  ],
  warnings: [],
};

function navigateTo(label: string) {
  fireEvent.click(
    within(
      screen.getByRole("navigation", { name: "Main navigation" }),
    ).getByRole("button", { name: new RegExp(label) }),
  );
}

function addedFolder(
  path = "/Users/antoineboxho/Developer/Personal/02_projects/talos-labs/target",
  name = "Talos build output",
): ScanItem {
  return {
    id: "manual-folder",
    category: "developer",
    name,
    path,
    bytes: 98_000_000_000,
    fileCount: 72_000,
    modifiedAt: 1_800_000_000_000,
    description: "Folder added manually. All contents will move to Trash.",
    source: "Added by you",
    risk: "review",
    cleanable: true,
    requiresAck: true,
  };
}

beforeAll(() => {
  // jsdom does not implement the native dialog methods used by the Tauri UI.
  HTMLDialogElement.prototype.showModal = function showModal() {
    this.setAttribute("open", "");
  };
  HTMLDialogElement.prototype.close = function close() {
    this.removeAttribute("open");
  };
});

beforeEach(() => {
  vi.clearAllMocks();
  bridge.scanSystem.mockResolvedValue(report);
  bridge.pickCleanupFolder.mockResolvedValue(null);
  bridge.trashItems.mockResolvedValue({
    trashedIds: [],
    reclaimedBytes: 0,
    failures: [],
  } satisfies CleanupResult);
  bridge.revealItem.mockResolvedValue(undefined);
  bridge.systemInsights.mockResolvedValue({ snapshots: [], processes: [], launchAgents: [], deletedOpenFiles: [], warnings: [] });
  bridge.openSystemSettings.mockResolvedValue(undefined);
});

afterEach(cleanup);

describe("Clean My Mac cleanup review", () => {
  it("requests a deep scan and shows its coverage", async () => {
    bridge.scanSystem.mockResolvedValue({ ...report, coverage: { mode: "deep", detectors: 44, visitedEntries: 1200, elapsedMs: 3400 } });
    render(<App />);
    await screen.findByText("Macintosh HD");
    expect(screen.getByLabelText("Deep scan")).toBeChecked();
    fireEvent.click(screen.getByRole("button", { name: "Scan again" }));
    await waitFor(() => expect(bridge.scanSystem).toHaveBeenLastCalledWith(true));
    expect(await screen.findByRole("status")).toHaveTextContent("Deep scan · 44 detectors · 1,200 entries checked · 3.4s");
  });

  it("loads system insights and supports retry after an error", async () => {
    bridge.systemInsights.mockRejectedValueOnce(new Error("Permission denied")).mockResolvedValueOnce({
      snapshots: [{ name: "snapshot-1", volume: "Macintosh HD", purgeable: true }],
      processes: [{ pid: 44, name: "Example", memoryBytes: 1_000_000, cpuPercent: 2 }],
      launchAgents: [{ path: "~/Library/LaunchAgents/helper.plist", label: "helper", program: null, programExists: false, system: false }],
      docker: { available: true, rows: [{ kind: "Local Volumes", total: 6, active: 4, size: "14.8 GB", reclaimable: "2 GB" }] },
      deletedOpenFiles: [], warnings: [],
    });
    render(<App />);
    await screen.findByText("Macintosh HD");
    navigateTo("System insights");
    expect(await screen.findByRole("alert")).toHaveTextContent("Permission denied");
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("snapshot-1")).toBeInTheDocument();
    expect(screen.getByText(/1 orphan candidates/)).toBeInTheDocument();
    expect(screen.getByText("Local Volumes")).toBeInTheDocument();
    expect(screen.getByText("14.8 GB")).toBeInTheDocument();
    expect(screen.getByText(/Volumes can contain valuable databases and project data/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Open Docker Desktop" }));
    expect(bridge.openSystemSettings).toHaveBeenCalledWith("docker");
  });

  it("filters results by source and sorts largest first", async () => {
    render(<App />);
    await screen.findByText("Macintosh HD");
    navigateTo("Caches & logs");
    fireEvent.change(screen.getByRole("combobox", { name: "Filter by source" }), { target: { value: "Browser" } });
    expect(await screen.findByText("Browser cache")).toBeInTheDocument();
    expect(screen.queryByText("Personal installer.dmg")).not.toBeInTheDocument();
    fireEvent.change(screen.getByRole("combobox", { name: "Filter by source" }), { target: { value: "all" } });
    fireEvent.change(screen.getByRole("combobox", { name: "Sort results" }), { target: { value: "oldest" } });
    expect(screen.getByText("Browser cache")).toBeInTheDocument();
  });

  it("adds and selects a manually chosen folder and requires risk acknowledgement", async () => {
    bridge.pickCleanupFolder.mockResolvedValue(addedFolder());
    render(<App />);
    await screen.findByText("Macintosh HD");

    fireEvent.click(screen.getByRole("button", { name: "Add folder" }));
    const folder = await screen.findByRole("checkbox", {
      name: "Select Talos build output",
    });
    expect(folder).toBeChecked();
    expect(screen.getAllByText("Added by you").length).toBeGreaterThan(0);
    expect(bridge.pickCleanupFolder).toHaveBeenCalledWith("scan-123");

    fireEvent.click(screen.getByRole("button", { name: "Review cleanup" }));
    const dialog = await screen.findByRole("dialog", {
      name: "Review your cleanup",
    });
    expect(
      within(dialog).getByText(
        "The added folder and all files inside it will move to Trash. Review its path and contents before continuing.",
      ),
    ).toBeInTheDocument();
    const moveButton = within(dialog).getByRole("button", {
      name: "Move to Trash",
    });
    expect(moveButton).toBeDisabled();
    fireEvent.click(
      within(dialog).getByRole("checkbox", {
        name: "I understand these files may be in use, contain history I need, or include personal data.",
      }),
    );
    fireEvent.click(moveButton);
    await waitFor(() =>
      expect(bridge.trashItems).toHaveBeenCalledWith(
        "scan-123",
        ["manual-folder"],
        true,
      ),
    );
  });

  it("leaves the report unchanged when folder selection is cancelled", async () => {
    bridge.pickCleanupFolder.mockResolvedValue(null);
    render(<App />);
    await screen.findByText("Macintosh HD");

    fireEvent.click(screen.getByRole("button", { name: "Add folder" }));
    await waitFor(() =>
      expect(bridge.pickCleanupFolder).toHaveBeenCalledWith("scan-123"),
    );
    expect(
      screen.queryByRole("checkbox", { name: "Select Talos build output" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("selects the existing item id when the picker returns a path already in the report", async () => {
    bridge.pickCleanupFolder.mockResolvedValue(
      addedFolder("~/Library/Caches/Browser", "Browser cache folder"),
    );
    render(<App />);
    await screen.findByText("Macintosh HD");
    navigateTo("Caches & logs");
    fireEvent.click(
      await screen.findByRole("checkbox", { name: "Select Browser cache" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Add folder" }));

    const added = await screen.findByRole("checkbox", {
      name: "Select Browser cache folder",
    });
    expect(added).toBeChecked();
    expect(screen.getAllByText("Added by you").length).toBeGreaterThan(0);
    expect(screen.getAllByRole("checkbox", { name: "Select Browser cache folder" })).toHaveLength(1);
    fireEvent.click(screen.getByRole("button", { name: "Review cleanup" }));
    const dialog = await screen.findByRole("dialog", {
      name: "Review your cleanup",
    });
    fireEvent.click(
      within(dialog).getByRole("checkbox", {
        name: "I understand these files may be in use, contain history I need, or include personal data.",
      }),
    );
    fireEvent.click(within(dialog).getByRole("button", { name: "Move to Trash" }));
    await waitFor(() =>
      expect(bridge.trashItems).toHaveBeenCalledWith(
        "scan-123",
        ["cache-old"],
        true,
      ),
    );
  });

  it("drops selected descendants when adding a folder that contains them", async () => {
    bridge.scanSystem.mockResolvedValue({
      ...report,
      items: report.items.map((item) =>
        item.id === "cache-old"
          ? {
              ...item,
              path: "/Users/antoineboxho/Developer/Personal/build/target/debug",
            }
          : item,
      ),
    });
    bridge.pickCleanupFolder.mockResolvedValue(
      addedFolder("/Users/antoineboxho/Developer/Personal/build/target"),
    );
    render(<App />);
    await screen.findByText("Macintosh HD");
    navigateTo("Caches & logs");
    fireEvent.click(
      await screen.findByRole("checkbox", { name: "Select Browser cache" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Add folder" }));
    const folder = await screen.findByRole("checkbox", {
      name: "Select Talos build output",
    });
    expect(folder).toBeChecked();
    expect(screen.getByText("98 GB selected")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Review cleanup" }));
    const dialog = await screen.findByRole("dialog", {
      name: "Review your cleanup",
    });
    expect(within(dialog).getByText("Talos build output")).toBeInTheDocument();
    expect(within(dialog).queryByText("Browser cache")).not.toBeInTheDocument();
  });

  it("allows manual review of recent files and downloads, while protected files stay unselectable", async () => {
    render(<App />);
    await screen.findByText("Macintosh HD");

    navigateTo("Agent sessions");
    const recent = await screen.findByRole("checkbox", {
      name: "Select Recent agent conversation",
    });
    expect(recent).toBeEnabled();
    fireEvent.click(recent);
    expect(recent).toBeChecked();

    navigateTo("Large files");
    const download = await screen.findByRole("checkbox", {
      name: "Select Personal installer.dmg",
    });
    expect(download).toBeEnabled();
    fireEvent.click(download);
    navigateTo("Developer files");
    expect(
      await screen.findByRole("checkbox", {
        name: "Select Protected configuration",
      }),
    ).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Review cleanup" }));
    const dialog = await screen.findByRole("dialog", {
      name: "Review your cleanup",
    });
    const moveButton = within(dialog).getByRole("button", {
      name: "Move to Trash",
    });
    expect(moveButton).toBeDisabled();
    fireEvent.click(
      within(dialog).getByRole("checkbox", {
        name: "I understand these files may be in use, contain history I need, or include personal data.",
      }),
    );
    expect(moveButton).toBeEnabled();
    fireEvent.click(moveButton);
    await waitFor(() =>
      expect(bridge.trashItems).toHaveBeenCalledWith(
        "scan-123",
        ["session-recent", "download-large"],
        true,
      ),
    );
  });

  it("selects recommended cache items without auto-selecting session history", async () => {
    render(<App />);
    await screen.findByText("Macintosh HD");
    navigateTo("Agent sessions");
    expect(
      await screen.findByRole("checkbox", {
        name: "Select Old agent conversation",
      }),
    ).not.toBeChecked();

    fireEvent.click(screen.getByRole("button", { name: "Select recommended" }));
    expect(screen.getByText("5 MB selected")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Review cleanup" }),
    ).toBeEnabled();

    navigateTo("Caches & logs");
    expect(
      await screen.findByRole("checkbox", { name: "Select Browser cache" }),
    ).toBeChecked();
    navigateTo("Agent sessions");
    expect(
      screen.getByRole("checkbox", { name: "Select Old agent conversation" }),
    ).not.toBeChecked();
  });

  it("shows eligible findings from the potential card and selects review-only items safely", async () => {
    const reviewOnlyReport: ScanReport = {
      ...report,
      items: report.items.map((item) =>
        item.risk === "protected" ? item : { ...item, risk: "review" },
      ),
    };
    bridge.scanSystem.mockResolvedValue(reviewOnlyReport);
    bridge.trashItems.mockResolvedValue({
      trashedIds: ["session-old", "session-recent", "cache-old", "download-large"],
      reclaimedBytes: 18_000_000,
      failures: [],
    } satisfies CleanupResult);
    render(<App />);
    await screen.findByText("Macintosh HD");

    fireEvent.click(
      screen.getByRole("button", { name: /Potential cleanup.*Show eligible findings/ }),
    );
    expect(screen.getByRole("button", { name: "Can clean" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    expect(screen.queryByRole("checkbox", { name: "Select Developer files" }))
      .not.toBeInTheDocument();
    expect(
      await screen.findByRole("checkbox", { name: "Select Old agent conversation" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("checkbox", { name: "Select Protected configuration" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Select recommended" }),
    ).not.toBeInTheDocument();
    const selectAll = screen.getByRole("button", { name: "Select all eligible" });
    expect(selectAll).toBeEnabled();
    fireEvent.click(selectAll);
    expect(screen.getByText("4 items ready for your review")).toBeInTheDocument();
    navigateTo("Developer files");
    expect(
      await screen.findByRole("checkbox", { name: "Select Protected configuration" }),
    ).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Review cleanup" }));

    const dialog = await screen.findByRole("dialog", { name: "Review your cleanup" });
    const moveButton = within(dialog).getByRole("button", { name: "Move to Trash" });
    expect(moveButton).toBeDisabled();
    fireEvent.click(moveButton);
    expect(bridge.trashItems).not.toHaveBeenCalled();

    fireEvent.click(
      within(dialog).getByRole("checkbox", {
        name: "I understand these files may be in use, contain history I need, or include personal data.",
      }),
    );
    expect(moveButton).toBeEnabled();
    fireEvent.click(moveButton);
    await waitFor(() =>
      expect(bridge.trashItems).toHaveBeenCalledWith(
        "scan-123",
        ["session-old", "session-recent", "cache-old", "download-large"],
        true,
      ),
    );
  });

  it("waits for confirmation and sends the scan token with only the chosen item ids", async () => {
    render(<App />);
    await screen.findByText("Macintosh HD");
    navigateTo("Caches & logs");
    fireEvent.click(
      await screen.findByRole("checkbox", { name: "Select Browser cache" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Review cleanup" }));

    const dialog = await screen.findByRole("dialog", {
      name: "Review your cleanup",
    });
    expect(within(dialog).getByText("Browser cache")).toBeInTheDocument();
    expect(bridge.trashItems).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Move to Trash" }));
    await waitFor(() =>
      expect(bridge.trashItems).toHaveBeenCalledWith(
        "scan-123",
        ["cache-old"],
        false,
      ),
    );
  });

  it("shows partial failures, removes moved entries, and explains Trash does not free disk space yet", async () => {
    bridge.trashItems.mockResolvedValue({
      trashedIds: ["cache-old"],
      reclaimedBytes: 5_000_000,
      freeBytesBefore: 250_000_000_000,
      freeBytesAfter: 270_000_000_000,
      volumeAfter: {
        ...report.volume,
        availableBytes: 270_000_000_000,
        freeBytes: 270_000_000_000,
      },
      failures: [
        {
          id: "session-old",
          message: "This conversation changed during the scan.",
        },
      ],
    } satisfies CleanupResult);
    render(<App />);
    await screen.findByText("Macintosh HD");

    navigateTo("Caches & logs");
    fireEvent.click(
      await screen.findByRole("checkbox", { name: "Select Browser cache" }),
    );
    navigateTo("Agent sessions");
    fireEvent.click(
      await screen.findByRole("checkbox", {
        name: "Select Old agent conversation",
      }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Review cleanup" }));
    fireEvent.click(
      await screen.findByRole("checkbox", {
        name: "I understand these files may be in use, contain history I need, or include personal data.",
      }),
    );
    fireEvent.click(
      await screen.findByRole("button", { name: "Move to Trash" }),
    );

    await waitFor(() =>
      expect(bridge.trashItems).toHaveBeenCalledWith("scan-123", [
        "session-old",
        "cache-old",
      ], true),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(/1 item moved to Trash/);
    expect(screen.getByRole("alert")).toHaveTextContent("Trash items still occupy disk space until Trash is emptied");
    expect(screen.getByRole("alert")).toHaveTextContent("This conversation changed during the scan.");
    expect(
      screen.queryByRole("checkbox", { name: "Select Browser cache" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("checkbox", { name: "Select Old agent conversation" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("checkbox", { name: "Select Old agent conversation" }),
    ).toBeEnabled();
    navigateTo("Overview");
    expect(screen.getByText("270 GB free")).toBeInTheDocument();
    expect(bridge.scanSystem).toHaveBeenCalledTimes(1);
    fireEvent.click(
      screen.getByRole("button", {
        name: "View moved files and original locations",
      }),
    );
    const receipt = await screen.findByRole("dialog", {
      name: "Your last cleanup",
    });
    expect(
      within(receipt).getByRole("textbox", {
        name: "Original location of Browser cache",
      }),
    ).toHaveValue("~/Library/Caches/Browser");
    expect(
      within(receipt).queryByText("Old agent conversation"),
    ).not.toBeInTheDocument();
  });

  it("searches the selected category by file name", async () => {
    render(<App />);
    await screen.findByText("Macintosh HD");
    navigateTo("Caches & logs");
    expect(await screen.findByText("Browser cache")).toBeInTheDocument();

    fireEvent.change(screen.getByRole("textbox", { name: "Search files" }), {
      target: { value: "missing" },
    });
    expect(await screen.findByText("No matching files")).toBeInTheDocument();
    expect(screen.queryByText("Browser cache")).not.toBeInTheDocument();
  });

  it("selects all recommendations across a batch larger than 200 items", async () => {
    const template = report.items.find((item) => item.id === "cache-old");
    if (!template) throw new Error("Cache fixture is missing");
    const manyItems: ScanReport = {
      ...report,
      items: Array.from({ length: 205 }, (_, index) => ({
        ...template,
        id: `cache-${index}`,
        name: `Browser cache ${index}`,
        path: `~/Library/Caches/Browser/${index}`,
      })),
    };
    bridge.scanSystem.mockResolvedValue(manyItems);
    render(<App />);
    await screen.findByText("Macintosh HD");

    fireEvent.click(screen.getByRole("button", { name: "Select recommended" }));
    expect(
      screen.getByText("205 items ready for your review"),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Review cleanup" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Move to Trash" }),
    );

    await waitFor(() => expect(bridge.trashItems).toHaveBeenCalledTimes(1));
    const ids = bridge.trashItems.mock.calls[0]?.[1] as string[];
    expect(bridge.trashItems.mock.calls[0]?.[0]).toBe("scan-123");
    expect(bridge.trashItems.mock.calls[0]?.[2]).toBe(false);
    expect(ids).toHaveLength(205);
    expect(ids).toEqual(
      Array.from({ length: 205 }, (_, index) => `cache-${index}`),
    );
  });
});
