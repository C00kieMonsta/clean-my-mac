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
import type { CleanupResult, ScanReport } from "@clean-my-mac/core";

const bridge = vi.hoisted(() => ({
  scanSystem: vi.fn(),
  trashItems: vi.fn(),
  revealItem: vi.fn(),
}));

vi.mock("./lib/bridge", () => ({
  previewMode: false,
  scanSystem: bridge.scanSystem,
  trashItems: bridge.trashItems,
  revealItem: bridge.revealItem,
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
      risk: "protected",
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
      cleanable: false,
      reason: "Manage this file in Finder.",
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
  bridge.trashItems.mockResolvedValue({
    trashedIds: [],
    reclaimedBytes: 0,
    failures: [],
  } satisfies CleanupResult);
  bridge.revealItem.mockResolvedValue(undefined);
});

afterEach(cleanup);

describe("Clean My Mac cleanup review", () => {
  it("keeps protected and Finder-only entries unselectable", async () => {
    render(<App />);
    await screen.findByText("Macintosh HD");

    navigateTo("Agent sessions");
    const recent = await screen.findByRole("checkbox", {
      name: "Select Recent agent conversation",
    });
    expect(recent).toBeDisabled();

    navigateTo("Large files");
    const download = await screen.findByRole("checkbox", {
      name: "Select Personal installer.dmg",
    });
    expect(download).toBeDisabled();
    expect(
      screen.getByRole("button", { name: "Review cleanup" }),
    ).toBeDisabled();
    expect(bridge.trashItems).not.toHaveBeenCalled();
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
      expect(bridge.trashItems).toHaveBeenCalledWith("scan-123", ["cache-old"]),
    );
  });

  it("shows partial failures, removes moved entries, and explains Trash does not free disk space yet", async () => {
    bridge.trashItems.mockResolvedValue({
      trashedIds: ["cache-old"],
      reclaimedBytes: 5_000_000,
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
      await screen.findByRole("button", { name: "Move to Trash" }),
    );

    await waitFor(() =>
      expect(bridge.trashItems).toHaveBeenCalledWith("scan-123", [
        "session-old",
        "cache-old",
      ]),
    );
    expect(await screen.findByRole("alert")).toHaveTextContent(
      "1 item moved to Trash",
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      "Empty Trash in Finder to free disk space.",
    );
    expect(screen.getByRole("alert")).toHaveTextContent(
      "This conversation changed during the scan.",
    );
    expect(
      screen.queryByRole("checkbox", { name: "Select Browser cache" }),
    ).not.toBeInTheDocument();
    expect(
      screen.getByRole("checkbox", { name: "Select Old agent conversation" }),
    ).toBeInTheDocument();
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

  it("limits the selection to 200 items when a scan finds more recommendations", async () => {
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
    expect(await screen.findByRole("status")).toHaveTextContent(
      "Selected the first 200 recommended items.",
    );
    expect(
      screen.getByText("200 items ready for your review"),
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Review cleanup" }));
    fireEvent.click(
      await screen.findByRole("button", { name: "Move to Trash" }),
    );

    await waitFor(() => expect(bridge.trashItems).toHaveBeenCalledTimes(1));
    const ids = bridge.trashItems.mock.calls[0]?.[1] as string[];
    expect(bridge.trashItems.mock.calls[0]?.[0]).toBe("scan-123");
    expect(ids).toHaveLength(200);
    expect(ids).toEqual(
      Array.from({ length: 200 }, (_, index) => `cache-${index}`),
    );
  });
});
