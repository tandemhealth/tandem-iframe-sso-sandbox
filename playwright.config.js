import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "e2e",
  timeout: 30_000,
  reporter: "list",
  use: {
    // Set PLAYWRIGHT_CHANNEL=chrome to use an installed Google Chrome instead
    // of the Playwright-managed Chromium (`npx playwright install chromium`).
    channel: process.env.PLAYWRIGHT_CHANNEL,
    headless: true,
  },
});
