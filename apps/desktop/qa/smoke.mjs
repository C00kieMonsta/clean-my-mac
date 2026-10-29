import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { chromium } from "playwright-core";

// Run against `pnpm dev`. The browser preview has no filesystem access.
const browser = await chromium.launch({
  executablePath:
    process.env.CHROME_PATH ||
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  headless: true,
});
try {
  const page = await browser.newPage({
    viewport: { width: 1280, height: 900 },
  });
  const errors = [];
  page.on("pageerror", (error) => errors.push(error.message));
  await page.goto(process.env.PREVIEW_URL || "http://127.0.0.1:1427");
  await page.getByText("Preview · sample data").waitFor();
  await page.getByText("Potential cleanup").waitFor();
  await mkdir("../../artifacts", { recursive: true });
  await page.screenshot({
    path: "../../artifacts/overview.png",
    fullPage: true,
  });
  await page
    .getByRole("button", { name: "Select recommended", exact: true })
    .click();
  await page
    .getByRole("button", { name: "Review cleanup", exact: true })
    .click();
  const dialog = page.getByRole("dialog");
  await dialog.waitFor();
  assert.equal(
    await dialog
      .getByRole("button", { name: "Move to Trash", exact: true })
      .isDisabled(),
    true,
  );
  assert.equal(
    await dialog
      .getByText("This is sample data. Open the desktop app to clean your Mac.")
      .isVisible(),
    true,
  );
  await page.screenshot({ path: "../../artifacts/review.png", fullPage: true });
  await dialog.getByRole("button", { name: "Keep files" }).click();
  await page
    .getByRole("navigation")
    .getByRole("button", { name: "Agent sessions" })
    .click();
  await page
    .getByRole("heading", { name: "Agent sessions", exact: true })
    .waitFor();
  assert.equal(
    await page
      .getByRole("checkbox", {
        name: "Select Recent Codex session",
        exact: true,
      })
      .isDisabled(),
    true,
  );
  await page
    .getByRole("textbox", { name: "Search files" })
    .fill("nothing-matches");
  await page.getByRole("heading", { name: "No matching files" }).waitFor();
  await page.getByRole("textbox", { name: "Search files" }).fill("");
  await page.setViewportSize({ width: 900, height: 640 });
  assert.equal(
    await page.evaluate(
      () => document.documentElement.scrollWidth > window.innerWidth,
    ),
    false,
  );
  await page.screenshot({
    path: "../../artifacts/agents-small.png",
    fullPage: true,
  });
  assert.deepEqual(errors, []);
  console.log(
    "Browser smoke passed: review gating, protected selection, navigation, search, and minimum viewport.",
  );
} finally {
  await browser.close();
}
