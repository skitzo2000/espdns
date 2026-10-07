// The controller's browser tests (make e2e): Chromium against a controller built from this
// checkout (serve.sh), on its own port and a throwaway data directory.
const { defineConfig } = require("@playwright/test");

const port = process.env.E2E_PORT || "18480";
process.env.E2E_PORT = port;
process.env.E2E_USER = "admin";
process.env.E2E_PASSWORD = "e2e test password";

module.exports = defineConfig({
  testDir: "tests",
  forbidOnly: true,
  retries: 0,
  workers: 1,
  reporter: "list",
  use: { baseURL: `http://127.0.0.1:${port}/`, browserName: "chromium" },
  webServer: {
    command: "./serve.sh",
    url: `http://127.0.0.1:${port}/login.html`,
    reuseExistingServer: false,
    timeout: 120000,
    stdout: "ignore",
    stderr: "pipe",
    // serve.sh removes its data directory on SIGTERM (the default, SIGKILL, would leave it).
    gracefulShutdown: { signal: "SIGTERM", timeout: 5000 },
  },
});
