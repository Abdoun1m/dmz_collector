import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  timeout: 30_000,
  fullyParallel: true,
  use: {
    baseURL: "http://127.0.0.1:9010",
    browserName: "chromium",
    viewport: { width: 1366, height: 768 },
  },
  webServer: {
    command: "node tests/ui-smoke-server.mjs",
    url: "http://127.0.0.1:9010",
    reuseExistingServer: !process.env.CI,
    timeout: 10_000,
  },
});
